"""H2: a goal-directed planner over Heimdall's public CLI.

A task is a goal (data). The planner holds one typed state, and the list of bindings
it was given and has not released. The goal names the first call; after that every
step is one row of TRANSITIONS, chosen from the state and the last answer's `code`
and `next.action`. Every answer is checked against the exit class of its process
(EXIT_CLASSES). A release Heimdall refuses is recorded, and the stop goes on with the
other bindings it holds. A release whose outcome is uncertain is never sent again: a
later stop, or the close, first observes what became of it. Nothing here reads an
answer's prose.
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
    # The complete list of this caller's bindings. H2 reads it for one thing only: what
    # became of a release whose answer was uncertain and named no operation.
    "bindings": {"argv": ("inspect", "bindings"), "options": {}, "answer": "bindings"},
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

# Seven states more than m07-plan §5a lists. Five hold what the next call needs:
# `observing`, an accepted operation that is neither an approval nor a provider wait;
# `reconciling`, the operation of an uncertain outcome, observed until it ends;
# `releasing`, the next binding to release: a stop that holds more than one binding,
# or one that begins where the state itself holds none;
# `observing_release`, a binding whose release was answered uncertainly, and the
# operation that answer named: a later stop observes it before it asks anything else;
# `inspecting_release`, the same where the answer named no operation: the binding's
# own state is read from the list of bindings.
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
    "observing_release": ("binding_id", "operation_id"),
    "inspecting_release": ("binding_id",),
    "stopped": (),
    "failed": ("code",),
    "inconsistent": ("code", "exit_code"),
    "unresolved": ("code", "operation_id"),
}
# A field a state may carry beside its own. `failed` names the operation of an
# uncertain outcome whenever one is known. Where a stop ends with a binding it did not
# release, it names the first such binding and the exit status of the answer about it.
OPTIONAL = {"failed": ("operation_id", "binding_id", "exit_code")}


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
# Six answers are the planner's own. Each stands where the code would, and no envelope
# can carry any of them: they are not words.
# The step limit ran out:
BOUND = "(the step limit)"
# The process ended in another exit class than the one documented for its answer, and
# the call was not about a release. The facts hold that answer's code and the exit status:
MISMATCH = "(the exit class)"
# The four readings of an answer about one binding's release (RELEASE_SAYS), beside
# `OK` for a release that was answered. For each, the planner has recorded the attempt.
# The release was not answered `OK` in its exit class: the binding stays held, and is
# set aside for this stop.
REFUSED = "(a refused release)"
# The release may have happened or not. The binding stays held and is set aside for
# this stop. The release is not sent again: a later stop observes it first.
UNCERTAIN = "(an uncertain release)"
# An observation says that the uncertain release happened: the binding is not held.
OBSERVED = "(a release observed)"
# An observation says that the uncertain release did not happen: one new release is sent.
NOT_RUN = "(a release that never ran)"
# Stands where a binding's state would, when the complete list does not name the binding:
ABSENT = "(not listed)"
ORIGIN = ("start", "discovered")
REQUESTING = ORIGIN + ("pending_provider",)
SENDING = REQUESTING + ("ready",)  # every state a request is sent from
IN_FLIGHT = ("observing", "pending_approval")
HELD = ("ready", "running")
RELEASABLE = HELD + ("releasing",)  # every state a release is sent from
OBSERVING = ("observing_release", "inspecting_release")  # an uncertain release is observed
STOPPING = RELEASABLE + OBSERVING  # every state a stop calls from
# Every state that makes a call that is not about a release:
CALLING = SENDING + IN_FLIGHT + ("reconciling",)

# What an answer says about the release of one binding. A row names the call; the
# answer's code and `next.action`; whether its exit class must fit (`fits`); one typed
# field of the answer and the value it must have; and the reading the transition table
# then gets. None stands for any. The first row that applies wins, and the last row for
# each call applies to every answer.
Says = namedtuple("Says", "call code action fits field value reading")
RELEASE_SAYS = (
    # The release itself. An uncertain answer is uncertain whatever its exit status.
    Says("release", "OUTCOME_UNKNOWN", None, None, None, None, UNCERTAIN),
    Says("release", "OK", "none", True, None, None, "OK"),
    # Any other code is a refusal. So is an answer whose exit class does not fit its code.
    Says("release", None, None, None, None, None, REFUSED),
    # Its operation, observed: the code is the operation's own once it has one.
    Says("observe", "OUTCOME_UNKNOWN", None, None, None, None, UNCERTAIN),
    Says("observe", "OK", "none", True, None, None, OBSERVED),
    Says("observe", "OK", None, None, None, None, UNCERTAIN),  # unfinished, or the wrong class
    # It ended with another code and reports no effect: the release never ran.
    Says("observe", None, "none", True, "data.effect_status", "none", NOT_RUN),
    Says("observe", None, None, None, None, None, UNCERTAIN),
    # Its binding's own state, in the complete list of this caller's bindings.
    Says("bindings", "OK", "none", True, "binding.state", "active", NOT_RUN),
    Says("bindings", "OK", "none", True, "binding.state", "released", OBSERVED),
    Says("bindings", "OK", "none", True, "binding.state", ABSENT, OBSERVED),
    Says("bindings", None, None, None, None, None, UNCERTAIN),
)
# What each reading is called in a record, and what each observing call observes.
OUTCOMES = {"OK": "released", OBSERVED: "released", REFUSED: "refused",
            UNCERTAIN: "outcome_unknown", NOT_RUN: "not_run"}
OBSERVED_BY = {"observe": "operation", "bindings": "bindings"}
# The outcomes that leave a binding held, and set it aside for the stop in progress.
SET_ASIDE = ("refused", "outcome_unknown")
# Today's `access release` takes no request ID (ADR-0013 §2.2), so an uncertain release
# has none to record, and there is no same-key replay to fall back on (ADR-0013 §7:
# forms without a request ID are not deduplicated by key). It can only be observed.
RELEASE_REQUEST_ID = None
DECISION = (("decision_ref", "next.decision_ref"), ("operation_id", "next.operation_id"))
PROVIDER = (("provider", "next.provider_interaction.provider"),
            ("kind", "next.provider_interaction.kind"))
CODE = (("code", "code"),)
STILL_UNKNOWN = (("code", "=OUTCOME_UNKNOWN"), ("operation_id", "state.operation_id"))
# The planner's own facts about a release (Planner.release_facts). The next binding the
# stop may ask about is `held.binding_id` when its release is to be sent, and
# `uncertain.binding_id` when its last release was answered uncertainly (with
# `uncertain.operation_id` when that answer named an operation). `unreleased.*` is the
# first binding this stop did not release: refused, or still uncertain.
NEXT_HELD = (("binding_id", "held.binding_id"),)
NEXT_OBSERVED = (("binding_id", "uncertain.binding_id"),
                 ("operation_id", "uncertain.operation_id"))
NEXT_INSPECTED = (("binding_id", "uncertain.binding_id"),)
UNRELEASED = (("code", "unreleased.code"), ("binding_id", "unreleased.binding_id"),
              ("exit_code", "unreleased.exit_code"))
# How a stop goes on once a binding has been dealt with, in this order: the next
# binding (a release to send, or an uncertain one to observe); and with none left to
# ask about, `failed`, naming the first binding this stop did not release.
ONWARD = (("releasing", NEXT_HELD),
          ("observing_release", NEXT_OBSERVED),
          ("inspecting_release", NEXT_INSPECTED),
          ("failed", UNRELEASED + (("operation_id", "unreleased.operation_id"),)),
          ("failed", UNRELEASED))
# A stop that released every binding it asked about ends in `stopped`.
ENDING = ONWARD + (("stopped", ()),)
# Each reading that deals with a binding: the states it is read in, and how the stop
# goes on from it. Only a binding that was released can end the stop in `stopped`.
DEALT_WITH = (("OK", RELEASABLE, ENDING), (OBSERVED, OBSERVING, ENDING),
              (REFUSED, RELEASABLE, ONWARD), (UNCERTAIN, STOPPING, ONWARD))

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
    # a stop: one binding for each step, until the planner holds no other to ask about.
    # A release that was answered, refused or uncertain, and an uncertain one observed
    # to have happened, each go on as ONWARD says (one row for each way)
    *(Row(states, reading, "none", to, takes)
      for reading, states, onward in DEALT_WITH for to, takes in onward),
    # an uncertain release observed not to have happened: one new release, of that binding
    Row(OBSERVING, NOT_RUN, "none", "releasing", (("binding_id", "state.binding_id"),)),
    # the exit class did not fit the answer to a call that is not about a release: stop
    # and report both
    Row(CALLING, MISMATCH, "none", "inconsistent", CODE + (("exit_code", "exit_code"),)),
)

# The exit class the CLI documents for each answer the table acts on
# (docs/api/local-protocol.md, "Exit classes": 0 success, 1 internal, 2 usage, 3 needs a
# person, 4 not allowed, 5 unavailable for now, 6 conflict, 7 uncertain). A key is a
# code, or a (code, next.action) pair where the class is not the code's own.
# `NOT_FOUND` has no row of its own: it is here for a release of a binding Heimdall
# does not know, so that refusal is checked like the others.
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
    "NOT_FOUND": 2,
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
    "observing_release": ("observe", None),
    "inspecting_release": ("bindings", None),
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


def entering(facts):
    """The state a stop enters for its next binding: the first way of ONWARD whose
    facts are there."""
    for to, takes in ONWARD:
        fields = {field: lookup(facts, path) for field, path in takes}
        if all(value is not None for value in fields.values()):
            return State(to, **fields)
    raise PlannerError("the stop has no binding to go on with")


def release_says(call, answer, fits):
    """What an answer says about a release: the reading of the first row of
    RELEASE_SAYS that applies. `fits` is whether its exit class fits its code."""
    for row in RELEASE_SAYS:
        if (row.call == call and row.code in (None, answer.code)
                and row.action in (None, answer.action) and row.fits in (None, fits)
                and (row.field is None or lookup(answer.facts, row.field) == row.value)):
            return row.reading
    raise PlannerError(f"no reading of a release for the call {call}")


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
    exit status yet. A code EXIT_CLASSES lacks has no row in TRANSITIONS either, and
    has no documented class here to check: as a refused release it is recorded with
    the exit status it came with. An answer about a release that fails this check is
    read by RELEASE_SAYS, and never by the row for a mismatch."""
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


def read_release(envelope, binding_id):
    """A release that was answered `OK` is about the binding asked for. Any other
    answer is returned as it is."""
    reading = read_envelope(envelope)
    require(reading.code != "OK" or lookup(reading.facts, "data.binding_id") == binding_id,
            "the answer is about another binding")
    return reading


def read_bindings(envelope, binding_id):
    """The complete list of this caller's bindings, reduced to what it says of one: the
    facts gain `binding.state`, that binding's own state, or ABSENT when the list does
    not name it. An answer that is not `OK` with a list of entries, or that gives the
    binding no one state, gains nothing, and so says nothing of the binding."""
    reading = read_envelope(envelope)
    listed = reading.facts["data"].get("bindings")
    if (reading.code != "OK" or not isinstance(listed, list)
            or not all(isinstance(entry, dict) for entry in listed)):
        return reading
    states = [entry.get("state") for entry in listed if entry.get("binding_id") == binding_id]
    if not states:
        states = [ABSENT]
    elif not _word(states[0]):
        return reading
    if any(state != states[0] for state in states):
        return reading
    return reading._replace(facts=dict(reading.facts, binding={"state": states[0]}))


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


def given_value(given, name, windows):
    """`name` in the environment this harness was given. Windows names its variables
    without regard to case, and Python's `os.environ` there holds them upper-cased
    (`SYSTEMROOT`), so a copy of it has no `SystemRoot` key: on Windows any spelling
    of the name is the variable."""
    value = given.get(name)
    if value is None and windows:
        wanted = name.upper()
        for key, candidate in given.items():
            if key.upper() == wanted:
                return candidate
    return value


def launch_environment(root, given, windows=None):
    """The three separate homes and fixture stores inside the scratch root, fixed
    PATH, LANG and TERM, and Windows system and scratch paths.

    `windows` says which platform's variables to build (the running one when omitted).

    The homes are checked by their real paths and passed on as they were given: a
    runtime is found under the spelling of the Heimdall home it was started with."""
    if windows is None:
        windows = os.name == "nt"
    require(root.is_absolute() and root.is_dir(), "the scratch root is not an absolute directory")
    real_root = Path(os.path.realpath(root))
    homes = {}
    for name in HOMES:
        value = given_value(given, name, windows)
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
    env.update((name, given_value(given, name, windows)) for name in HOMES)
    for name, prefix in STORES.items():
        value = given_value(given, name, windows) or ""
        path = Path(value[len(prefix):])
        require(value.startswith(prefix) and path.is_absolute(),
                f"{name} is not set to {prefix}<absolute path>")
        try:
            real = path.resolve()
        except (OSError, RuntimeError):
            raise PlannerError(f"{name} could not be resolved") from None
        require(real_root in real.parents and (not real.exists() or real.is_file()),
                f"{name} is not a file path inside the scratch root")
        env[name] = value
    env["HEIMDALL_TEST_SECRET_STORE"] = "scratch"
    if windows:
        env.update(windows_launch_variables(
            given_value(given, "SystemRoot", windows) or "", env["HOME"]))
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
        # Every call this planner made about the release of a binding, oldest first:
        # the binding, who called (`by`: a stop goal, or the close), the outcome, the
        # answer's code and the exit status of its process. An observation also says
        # what it observed.
        self.attempts = []
        # How many of them came before the stop in progress. A binding that stop was
        # refused, or left uncertain, is set aside: the stop does not ask about it again.
        self.stop_began = 0
        # Each held binding whose release was answered uncertainly and has not been
        # observed to an end since: the request ID of that release (none today), and
        # the operation its answer named, when it named one. Its release is not sent
        # again while it is here.
        self.uncertain = {}
        self.by = "stop"

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
            reading = read_release(envelope, values["binding_id"])
        elif kind == "bindings":
            reading = read_bindings(envelope, values["binding_id"])
        else:
            reading = read_envelope(envelope)
        return reading._replace(exit=done.returncode)

    def releasable(self):
        """The bindings the stop in progress may still ask about, oldest first: those
        held, without the ones it was refused or left uncertain."""
        aside = {attempt["binding_id"] for attempt in self.attempts[self.stop_began:]
                 if attempt["outcome"] in SET_ASIDE}
        return [held for held in self.held if held not in aside]

    def approach(self, binding_id):
        """The planner's own facts about a binding a stop is to ask about next:
        `uncertain.*` when its last release was answered uncertainly, else `held.*`."""
        if binding_id not in self.uncertain:
            return {"held": {"binding_id": binding_id}, "uncertain": {}}
        uncertain = {"binding_id": binding_id}
        if "operation_id" in self.uncertain[binding_id]:
            uncertain["operation_id"] = self.uncertain[binding_id]["operation_id"]
        return {"held": {}, "uncertain": uncertain}

    def unreleased(self):
        """The first attempt of the stop in progress that left its binding held."""
        return next((attempt for attempt in self.attempts[self.stop_began:]
                     if attempt["outcome"] in SET_ASIDE), None)

    def release_facts(self, binding_id):
        """The planner's own facts for an answer about the release of `binding_id`: the
        next binding the stop may ask about beside this one (`approach`), when there is
        one; and the first binding this stop did not release (`unreleased.*`), when
        there is one. An uncertain one is named with the code `OUTCOME_UNKNOWN`."""
        others = [held for held in self.releasable() if held != binding_id]
        facts = self.approach(others[-1]) if others else {"held": {}, "uncertain": {}}
        facts["unreleased"] = {}
        first = self.unreleased()
        if first is not None:
            uncertain = first["outcome"] == "outcome_unknown"
            facts["unreleased"] = {"code": "OUTCOME_UNKNOWN" if uncertain else first["code"]}
            for field in ("binding_id", "exit_code", "operation_id"):
                if field in first:
                    facts["unreleased"][field] = first[field]
        return facts

    def settle(self, call, answer, problem, binding_id):
        """Read an answer about the release of `binding_id` (RELEASE_SAYS), record the
        attempt, and return the planner's own reading of it for the table. `problem`
        says how the answer's exit class did not fit, when it did not.

        A binding that was released leaves `held`. Any other stays. An uncertain
        release is remembered with the operation its answer named, so that a later
        stop observes it and does not send it again."""
        says = release_says(call, answer, problem is None)
        attempt = {"binding_id": binding_id, "by": self.by, "outcome": OUTCOMES[says],
                   "code": answer.code, "exit_code": answer.exit}
        if call in OBSERVED_BY:
            attempt["observed"] = OBSERVED_BY[call]
        if lookup(answer.facts, "binding.state") is not None:
            attempt["state"] = answer.facts["binding"]["state"]
        if problem is not None:
            # Heimdall's own table gives each code one exit class.
            attempt.update(inconsistent=True, detail=f"{problem}; a probable product defect")
        if says == UNCERTAIN:
            if call == "release":
                # The operation the answer's `next` names, else the envelope's own.
                self.uncertain[binding_id] = {"request_id": RELEASE_REQUEST_ID}
                for operation in (answer.facts.get("operation_id"),
                                  lookup(answer.facts, "next.operation_id")):
                    if FIELD_CHECKS["operation_id"](operation):
                        self.uncertain[binding_id]["operation_id"] = operation
            attempt.update(self.uncertain[binding_id])
        else:
            self.uncertain.pop(binding_id, None)
        if OUTCOMES[says] == "released":
            self.held = [held for held in self.held if held != binding_id]
        self.attempts.append(attempt)
        return Reading(says, "none", answer.effect,
                       dict(answer.facts, **self.release_facts(binding_id)), answer.exit)

    def recorded(self, outcome, since=0):
        """The attempts from `since` on that had this outcome, as a record lists them."""
        return [{key: value for key, value in attempt.items() if key not in ("by", "outcome")}
                for attempt in self.attempts[since:] if attempt["outcome"] == outcome]

    @property
    def refusals(self):
        """Every release Heimdall refused, oldest first."""
        return self.recorded("refused")

    def by_binding(self):
        """Each binding with an attempt that did not release it: whether it is still
        held, and every attempt about it in order."""
        named = {}
        for attempt in self.attempts:
            if attempt["outcome"] != "released":
                named[attempt["binding_id"]] = {"held": attempt["binding_id"] in self.held,
                                                "attempts": []}
        for attempt in self.attempts:
            if attempt["binding_id"] in named:
                named[attempt["binding_id"]]["attempts"].append(
                    {key: value for key, value in attempt.items() if key != "binding_id"})
        return named

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

    def begin(self, goal, spec, new=None):
        if spec["begin"] == "held":
            # A stop begins wherever a binding is held. It goes on from a state that holds
            # one. From any other state (a goal that failed, a stop the step limit cut
            # short and whose binding is gone) it begins at the newest binding on the list.
            # Only `releasing` or an observing state, with a binding still to ask about,
            # is a stop cut short: this one goes on with it, and what that one set aside
            # stays set aside. From any other state the stop is a new one and asks about
            # everything held. The close says which it is for each of its rounds (`new`).
            if new is None:
                new = not (self.state.name in ("releasing",) + OBSERVING
                           and self.state.fields["binding_id"] in self.releasable())
            if new:
                self.stop_began = len(self.attempts)
            candidates = self.releasable()
            require(candidates, f"nothing is held to stop in state {self.state.name}")
            first = self.state.fields.get("binding_id") if self.state.name in STOPPING else None
            if first not in candidates:
                first = candidates[-1]
            # A binding whose release is uncertain is observed first, whatever state
            # holds it. Any other is released from the state that holds it.
            if (first in self.uncertain or self.state.name not in RELEASABLE
                    or self.state.fields["binding_id"] != first):
                self.state = entering(self.approach(first))
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

    def pursue(self, goal, metrics, new=None):
        """Work toward one goal. Returns a short account of how it was met."""
        spec = GOALS[goal["goal"]]
        self.begin(goal, spec, new)
        expected = goal.get("expect_refusal")
        call = spec["first"]
        if self.state.name in OBSERVING:  # a stop that begins at an uncertain release
            call = FOLLOW[self.state.name][0]
        for _ in range(MAX_STEPS):
            answer = self.invoke(call, goal, metrics)
            before = self.state
            if answer.action in INVALID_REQUEST_ACTIONS:
                metrics["invalid_retries"] += 1
            reading, problem = check_exit(answer)
            about_release = call == "release" or before.name in OBSERVING
            if about_release:
                # An answer about a release is read by RELEASE_SAYS, its exit class
                # with it, and the table gets the planner's own reading. It never ends
                # the stop where it stands: the other bindings are still asked about.
                answer = reading = self.settle(call, answer, problem, before.fields["binding_id"])
                problem = None
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
            if after.name == "stopped" and self.child is not None:
                child, self.child = self.child, None
                status = child.end()
                metrics["child_exit_code"] = status
                require(status == 0, f"the child ended with exit {status}")
            if after.name == "failed":
                require(row is not None, problem)
                if about_release:  # the stop ends: it names the first binding it did not release
                    problem = self.unreleased().get("detail")
                require(expected == after.fields["code"],
                        problem or f"failed: {after.fields['code']}")
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
        own handle. Returns the bindings that left the list here and those still held.
        A binding Heimdall refused to release, or whose release is still uncertain, is
        still held, and `attempts` names it.

        The whole of it is one stop of its own, made in rounds that are each bounded
        like any goal: it asks about every held binding once, whatever an earlier stop
        was answered, and a binding it does not release is not asked about again in a
        later round. An uncertain release of an earlier stop is observed, not sent
        again. One of its own is left as it is: the close does not observe it. A round
        that makes no attempt ends it, so each round but the last leaves fewer bindings
        to ask about, and the whole is bounded too."""
        before = list(self.held)
        self.by = "close"
        try:
            for round_ in range(2 * len(before)):  # at most two calls for a binding
                left = len(self.attempts)
                try:
                    self.pursue({"goal": "stop"}, new_metrics(), new=round_ == 0)
                except (PlannerError, OSError):
                    pass
                if left == len(self.attempts) or not self.releasable():
                    break
        finally:
            self.by = "stop"
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
    success, started, attempted = False, time.monotonic(), len(planner.attempts)
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
                  held=list(planner.held),
                  refused_releases=planner.recorded("refused", attempted),
                  outcome_unknown=planner.recorded("outcome_unknown", attempted))
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
    # Every binding with an attempt that did not release it, in the goals and then in the
    # close, with all its attempts in order: each fails the run.
    unreleased = planner.by_binding()
    print(json.dumps({"harness": "H2", "call_set": CALL_SET_SOURCE, "tasks": tasks,
                      "close": closing, "release_attempts": unreleased}))
    return int(any(not task["success"] for task in tasks) or bool(closing["held"])
               or bool(unreleased))


if __name__ == "__main__":
    sys.exit(main())
