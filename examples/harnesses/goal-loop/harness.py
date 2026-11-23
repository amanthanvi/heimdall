"""H2: a goal-directed planner over Heimdall's public CLI.

A task is a goal (data). The planner holds one typed state, and the list of bindings
it was given and has not released. The goal names the first call; after that every
step is one row of TRANSITIONS, chosen from the state and the last answer's `code`
and `next.action`. The exit status of every answer's process is checked against the
class documented for the answer: the installed code table's where discovery read it,
else the frozen EXIT_CLASSES. A release Heimdall refuses is recorded, and the stop
goes on with the other bindings it holds. A release whose outcome is uncertain is
never sent again: a later stop, or the close, first observes what became of it. A
release that was started and brought no answer is uncertain too. One new release
follows only where the uncertain answer named an operation and that operation, once
ended without succeeding, says that the release did not happen. An operation is read
by the typed state of its view (OPERATION_STATES). A request (`access ensure`, `run`)
that was started and brought no answer is remembered in the same way: it may have made
a binding this planner was never told of. It is never sent again. A later stop, or the
close, observes what became of it, and releases a binding that shows only where it can
be the request's own. So is a request answered `OUTCOME_UNKNOWN` whose operation was
still unfinished at the step limit, and one answered `ACCEPTED` whose operation could
not be observed. Nothing here reads an answer's prose.
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


class NoAnswer(PlannerError):
    """A call brought no answer the harness can use. `reading` is the planner's own
    answer that stands in for it (`no_answer`) where the call was about a release."""

    def __init__(self, problem, reading):
        super().__init__(problem)
        self.reading = reading


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
    # The same list, read for one other thing: the binding it names that can be the
    # request's own, for a request that brought no answer and named no operation.
    "work": {"argv": ("inspect", "bindings"), "options": {}, "answer": "work"},
}
# The calls that are requests: each asks Heimdall to change something, and carries a
# request ID of its own. A record calls each one by the command it runs.
REQUESTS = {name: " ".join(part for part in call["argv"][:2] if not part.startswith("-"))
            for name, call in LOCAL_CALL_SET.items() if "{request_id}" in call["argv"]}
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

# Nine states more than m07-plan §5a lists. Seven hold what the next call needs:
# `observing`, an accepted operation that is neither an approval nor a provider wait;
# `reconciling`, the operation of an uncertain outcome, observed until it ends;
# `releasing`, the next binding to release: a stop that holds more than one binding,
# or one that begins where the state itself holds none;
# `observing_release`, a binding whose release was answered uncertainly, and the
# operation that answer named: a later stop waits on it before it asks anything else;
# `inspecting_release`, the same where the answer named no operation: the binding's
# own state is read from the list of bindings, and no release follows from there;
# `observing_request`, a request that brought no answer, or whose operation was left
# open, and the operation it named: a later stop waits on it before it asks about any
# binding; `inspecting_request`, the same where it named no operation: the list of
# bindings is read for a binding that can be that request's own.
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
    "observing_request": ("request_id", "operation_id"),
    "inspecting_request": ("request_id", "work_id"),
    "stopped": (),
    "failed": ("code",),
    "inconsistent": ("code", "exit_code"),
    "unresolved": ("code", "operation_id"),
}
# A field a state may carry beside its own. `failed` names the operation of an
# uncertain outcome whenever one is known. Where a stop ends with a binding it did not
# release, it names the first such binding, and the exit status of the answer about it
# when its process had one. Where a request brought no answer, or a stop could not
# learn what became of one, it names that request.
OPTIONAL = {"failed": ("operation_id", "binding_id", "exit_code", "request_id")}


def _identifier(prefix):
    pattern = re.compile(prefix + r"_[A-Za-z0-9._:-]{1,120}")
    return lambda value: isinstance(value, str) and pattern.fullmatch(value) is not None


def _word(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", value) is not None


def _label(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None


FIELD_CHECKS = {
    "operation_id": _identifier("op"),
    "decision_ref": _identifier("dec"),
    "binding_id": _identifier("binding"),
    "request_id": _label,
    "work_id": _label,
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
# Fifteen answers are the planner's own. Each stands where the code would, and no envelope
# can carry any of them: they are not words.
# The step limit ran out:
BOUND = "(the step limit)"
# The process ended in another exit class than the one documented for its answer, and
# the call was not about a release. The facts hold that answer's code and the exit status:
MISMATCH = "(the exit class)"
# A call brought no answer (`no_answer`). The CLI could not be started, so nothing was
# sent:
NOT_STARTED = "(not started)"
# The call was started and may have reached Heimdall, and no answer that can be used
# came of it: it ran past its time limit, or what it printed is not one envelope about
# what was asked. The facts hold what a first complete line did say:
UNANSWERED = "(no answer)"
# Why a call brought no answer, as an attempt records it (`fault`), and the answer of
# the planner's own that stands in for it.
FAULTS = {"not_started": NOT_STARTED, "timed_out": UNANSWERED, "unreadable": UNANSWERED}
# The eight readings of an answer about one binding's release (RELEASE_SAYS), beside
# `OK` for a release that was answered. For each, the planner has recorded the attempt.
# The release was not answered `OK` in its exit class: the binding stays held, and is
# set aside for this stop.
REFUSED = "(a refused release)"
# The release may have happened or not. The binding stays held and is set aside for
# this stop. The release is not sent again: a later stop observes it first.
UNCERTAIN = "(an uncertain release)"
# The release was started and brought no answer: it may have happened or not, as after
# an uncertain answer, and it is treated the same way.
SILENT = "(a release with no answer)"
# The release was not sent: the CLI could not be started. The binding stays held and
# is set aside for this stop. A later stop sends it.
UNSENT = "(a release not sent)"
# An observation says that the uncertain release happened: the binding is not held.
OBSERVED = "(a release observed)"
# The operation the uncertain answer named has ended, and its result says that the
# release did not happen: one new release is sent. No other reading leads to one.
NOT_RUN = "(a release that never ran)"
# An observation does not say what became of the uncertain release: the binding stays
# held and is set aside for this stop, and nothing is sent.
STILL_UNCERTAIN = "(a release still unknown)"
# The complete list of bindings does not name the binding. It is not held, and it is
# not recorded as released: it may as well have expired or been revoked.
NOT_LISTED = "(a binding not listed)"
# Stands where a binding's state would, when the complete list does not name the binding:
ABSENT = "(not listed)"
# The three readings of an observation of a request that brought no answer
# (REQUEST_SAYS). The request itself is read by its fault: NOT_STARTED was not sent, and
# UNANSWERED may have reached Heimdall and made a binding, so it is remembered.
# An observation says that the request made a binding, and names it: the binding is
# held from here on, and released like any other.
FOUND = "(a request observed)"
# The operation the request named has ended, and its result says that the request did
# not happen: there is nothing to release.
NEVER_RAN = "(a request that never ran)"
# An observation names a binding the request made, as for FOUND, but its process ended
# in another exit class than the one documented for it. The binding is held from here
# on, and released like any other, still marked `inconsistent`. The request stays
# uncertain (ruled 2026-11-23: cleanup is the safer side).
MISFIT = "(a binding found out of its exit class)"
# An observation does not say what became of the request: it stays uncertain, and
# nothing is sent.
STILL_OPEN = "(a request still unknown)"
# Stand where the list's word on a request would: it names exactly one binding that can
# be the request's own (`work.matching`) and that this planner was never given; none; or
# more than one. Only the first is evidence (ruled 2026-11-23).
NEW, NONE_NEW, SEVERAL = "one", "none", "several"
ORIGIN = ("start", "discovered")
REQUESTING = ORIGIN + ("pending_provider",)
SENDING = REQUESTING + ("ready",)  # every state a request is sent from
IN_FLIGHT = ("observing", "pending_approval")
# The state that waits on the accepted operation of a request (`ACCEPTED`). A wait in it
# that brings no answer leaves the request uncertain: it is remembered like a request
# that brought none (ruled 2026-11-23).
TRACKED = ("observing",)
HELD = ("ready", "running")
RELEASABLE = HELD + ("releasing",)  # every state a release is sent from
WAITING = ("observing_release",)  # the operation of an uncertain release is waited on
INSPECTING = ("inspecting_release",)  # the binding's own state is read from the list
OBSERVING = WAITING + INSPECTING  # an uncertain release is observed
ASKING_BY_WAIT = ("observing_request",)  # the operation of an unanswered request is waited on
ASKING_BY_LIST = ("inspecting_request",)  # the list is read for a binding that is its own
ASKING = ASKING_BY_WAIT + ASKING_BY_LIST  # an unanswered request is observed
STOPPING = RELEASABLE + OBSERVING + ASKING  # every state a stop calls from
# Every state that makes a call that is not about a release:
CALLING = SENDING + IN_FLIGHT + ("reconciling",)

# The states of an operation, from the published schema (`OperationState` in
# schemas/public-api/envelope.schema.json), in one table. For each state: whether the
# operation is still going (`active`); whether the state is terminal (the schema's
# "settled": the operation ended, and what its view says will not change); whether it
# is the terminal state of an operation that succeeded; and the exit class of an
# observation that found the operation in it (None: the class of the operation's own
# code). An operation in a state this table lacks is read as one that has not ended.
Stage = namedtuple("Stage", "active terminal succeeded exit")
OPERATION_STATES = {
    "queued": Stage(True, False, False, 5),
    "running": Stage(True, False, False, 5),
    "awaiting_approval": Stage(True, False, False, 5),
    "succeeded": Stage(False, True, True, None),
    "failed": Stage(False, True, False, None),
    "cancelled": Stage(False, True, False, None),
    # Neither: nothing is running, and it is unresolved until a reconciliation settles it.
    "outcome_unknown": Stage(False, False, False, 7),
}
# The states whose view has the last word on the operation: it succeeded, or it ended
# without succeeding.
SUCCEEDED = tuple(name for name, stage in OPERATION_STATES.items() if stage.succeeded)
UNSUCCESSFUL = tuple(name for name, stage in OPERATION_STATES.items()
                     if stage.terminal and not stage.succeeded)
# The states in which the view's own code is the answer's: the operation is not going.
OVER = tuple(name for name, stage in OPERATION_STATES.items() if not stage.active)

# What an answer says about the release of one binding. A row names the call; the
# answer's code and `next.action`; whether its exit class must fit (`fits`); the typed
# fields of the answer it wants, each with the values it may have; and the reading the
# transition table then gets. None stands for any, and so does no field. The first row
# that applies wins, and the last row for each call applies to every answer.
Says = namedtuple("Says", "call code action fits wants reading")
RELEASE_SAYS = (
    # The release itself. An uncertain answer is uncertain whatever its exit status,
    # and so is a release that was started and brought no answer.
    Says("release", "OUTCOME_UNKNOWN", None, None, (), UNCERTAIN),
    Says("release", UNANSWERED, None, None, (), SILENT),
    Says("release", NOT_STARTED, None, None, (), UNSENT),
    Says("release", "OK", "none", True, (), "OK"),
    # Any other code is a refusal. So is an answer whose exit class does not fit its code.
    Says("release", None, None, None, (), REFUSED),
    # Its operation, waited on once, and read by the typed `state` of its view: the
    # code is the operation's own once that state says the operation is over. A wait
    # that brought no answer settles nothing.
    Says("observe", "OUTCOME_UNKNOWN", None, None, (), STILL_UNCERTAIN),
    Says("observe", UNANSWERED, None, None, (), STILL_UNCERTAIN),
    Says("observe", NOT_STARTED, None, None, (), STILL_UNCERTAIN),
    # Only a terminal view of an operation that succeeded is evidence of a release.
    Says("observe", "OK", "none", True, (("data.state", SUCCEEDED),), OBSERVED),
    # Unfinished when the wait ran out, in no state that says it succeeded, or in the
    # wrong class:
    Says("observe", "OK", None, None, (), STILL_UNCERTAIN),
    # It ended without succeeding, with another code, and reports no effect: the
    # release did not happen. Only a terminal view says so.
    Says("observe", None, "none", True,
         (("data.state", UNSUCCESSFUL), ("data.effect_status", ("none",))), NOT_RUN),
    Says("observe", None, None, None, (), STILL_UNCERTAIN),
    # Its binding's own state, in the complete list of this caller's bindings. No row
    # here reads NOT_RUN: the list alone never leads to a new release.
    Says("bindings", "OK", "none", True, (("binding.state", ("released",)),), OBSERVED),
    Says("bindings", "OK", "none", True, (("binding.state", (ABSENT,)),), NOT_LISTED),
    # An `active` binding alone is not evidence that the release never ran: it may not
    # have been applied yet (ruled 2026-11-22).
    Says("bindings", "OK", "none", True, (("binding.state", ("active",)),), STILL_UNCERTAIN),
    Says("bindings", None, None, None, (), STILL_UNCERTAIN),
)
# What each reading is called in a record, and what each observing call observes.
OUTCOMES = {"OK": "released", OBSERVED: "released", REFUSED: "refused",
            UNCERTAIN: "outcome_unknown", SILENT: "unanswered", UNSENT: "not_sent",
            STILL_UNCERTAIN: "still_unknown", NOT_RUN: "not_run", NOT_LISTED: "not_listed"}
OBSERVED_BY = {"observe": "operation", "bindings": "bindings"}
# The readings after which a release is remembered as uncertain, with the operation its
# answer named when it named one: a later stop observes it before it sends anything.
REMEMBERED = (UNCERTAIN, SILENT)
# The outcomes after which a release is uncertain: by its own answer, by having none,
# or by an observation that did not say what became of it.
UNKNOWN = ("outcome_unknown", "unanswered", "still_unknown")
# The outcomes that leave a binding held, and set it aside for the stop in progress.
SET_ASIDE = ("refused", "not_sent") + UNKNOWN
# The outcomes that take a binding off the list of those held. Only the first is a release.
NOT_HELD = ("released", "not_listed")
# The lists of a goal's record, and the outcome each one holds the attempts of.
RECORDED = {"refused_releases": "refused", "outcome_unknown": "outcome_unknown",
            "unanswered": "unanswered", "not_sent": "not_sent",
            "still_unknown": "still_unknown", "not_listed": "not_listed"}
# What an observation says about a request that brought no answer: the rows are read
# as those of RELEASE_SAYS are. A wanted field may name a check where it has no fixed
# values. No row sends the request again, and no reading leads to that.
REQUEST_SAYS = (
    # Its operation, waited on once and read by the typed `state` of its view. A wait
    # that brought no answer settles nothing.
    Says("observe", "OUTCOME_UNKNOWN", None, None, (), STILL_OPEN),
    Says("observe", UNANSWERED, None, None, (), STILL_OPEN),
    Says("observe", NOT_STARTED, None, None, (), STILL_OPEN),
    # Only a terminal view of an operation that succeeded, and that names the binding
    # it made, is evidence of a binding.
    Says("observe", "ACCESS_READY", "none", True,
         (("data.state", SUCCEEDED), ("data.result.binding_id", FIELD_CHECKS["binding_id"])), FOUND),
    # The same in another exit class: the binding is held all the same.
    Says("observe", "ACCESS_READY", "none", False,
         (("data.state", SUCCEEDED), ("data.result.binding_id", FIELD_CHECKS["binding_id"])), MISFIT),
    # A success that names no usable binding, or that its state does not bear out; and
    # an operation unfinished when the wait ran out, or in the wrong class:
    Says("observe", "ACCESS_READY", None, None, (), STILL_OPEN),
    Says("observe", "OK", None, None, (), STILL_OPEN),
    # It ended without succeeding, with another code, and reports no effect: the
    # request did not happen. Only a terminal view says so.
    Says("observe", None, "none", True,
         (("data.state", UNSUCCESSFUL), ("data.effect_status", ("none",))), NEVER_RAN),
    Says("observe", None, None, None, (), STILL_OPEN),
    # The complete list of this caller's bindings, read for the request. The one binding
    # it names `active` that can be the request's own by every typed field the list
    # offers (ATTRIBUTION), and that this planner was never given, is a binding to
    # release. None, or more than one, says nothing: nothing is released (ruled
    # 2026-11-23). A list that names none is no evidence that the request never ran: it
    # may not have been applied yet.
    Says("work", "OK", "none", True, (("work.found", (NEW,)),), FOUND),
    Says("work", "OK", "none", False, (("work.found", (NEW,)),), MISFIT),
    Says("work", None, None, None, (), STILL_OPEN),
)
# What each reading of a request is called in a record: the request's own fault, then
# the observations. And what each observing call observes.
REQUEST_OUTCOMES = {UNANSWERED: "unanswered", NOT_STARTED: "not_sent", FOUND: "binding_found",
                    NEVER_RAN: "not_run", STILL_OPEN: "still_unknown", MISFIT: "still_unknown"}
REQUEST_OBSERVED_BY = {"observe": "operation", "work": "bindings"}
# The readings after which nothing more is to be learned of a request, and those that
# give this planner a binding to hold.
SETTLED = (FOUND, NEVER_RAN)
GIVING = (FOUND, MISFIT)
# The states a request's goal can end in with the request answered and its operation
# still open, and the outcome the request's attempt then records: answered
# `OUTCOME_UNKNOWN`, and unfinished at the step limit (ruled 2026-11-23). The request is
# remembered with that operation, as one that brought no answer is.
KEPT = {"unresolved": "outcome_unknown"}
# The lists of a goal's record that are about requests, and the outcome each one holds
# the attempts of. They stand beside the lists about releases (RECORDED).
REQUEST_RECORDED = {"requests_outcome_unknown": "outcome_unknown",
                    "requests_unanswered": "unanswered", "requests_not_sent": "not_sent",
                    "requests_still_unknown": "still_unknown"}
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
# first binding this stop did not release: refused, not sent, or still uncertain.
NEXT_HELD = (("binding_id", "held.binding_id"),)
NEXT_OBSERVED = (("binding_id", "uncertain.binding_id"),
                 ("operation_id", "uncertain.operation_id"))
NEXT_INSPECTED = (("binding_id", "uncertain.binding_id"),)
NAMED = (("code", "unreleased.code"), ("binding_id", "unreleased.binding_id"))
UNRELEASED = NAMED + (("exit_code", "unreleased.exit_code"),)
ITS_OPERATION = (("operation_id", "unreleased.operation_id"),)
# The planner's own facts about a request that brought no answer (Planner.unanswered,
# Planner.untracked, Planner.release_facts). `request.*` is that request where it is the one just sent, and
# otherwise the next one a stop is to observe, with `request.operation_id` when it
# named an operation. `unreleased.request_id` names a request where the first thing
# this stop could not settle is one.
UNKNOWN_CODE = (("code", "=OUTCOME_UNKNOWN"),)
ITS_REQUEST = (("request_id", "request.request_id"),)
NAMED_BY_IT = (("operation_id", "request.operation_id"),)
NEXT_ASKED = ITS_REQUEST + NAMED_BY_IT
NEXT_LISTED = ITS_REQUEST + (("work_id", "request.work_id"),)
UNSETTLED = (("code", "unreleased.code"), ("request_id", "unreleased.request_id"))
# How a stop goes on once a binding has been dealt with, in this order: the next
# binding (a release to send, or an uncertain one to observe); and with none left to
# ask about, `failed`, naming the first binding this stop did not release. The call
# about that binding has no exit status where it was never started, or was ended by
# this harness when it ran past its time limit. Where the first thing the stop could not
# settle is a request, `failed` names that request.
ONWARD = (("releasing", NEXT_HELD),
          ("observing_release", NEXT_OBSERVED),
          ("inspecting_release", NEXT_INSPECTED),
          ("failed", UNRELEASED + ITS_OPERATION),
          ("failed", UNRELEASED),
          ("failed", NAMED + ITS_OPERATION),
          ("failed", NAMED),
          ("failed", UNSETTLED + ITS_OPERATION),
          ("failed", UNSETTLED))
# A stop that released every binding it asked about ends in `stopped`.
ENDING = ONWARD + (("stopped", ()),)
# A stop observes every request that brought no answer before it asks about a binding:
# one of them may give a binding, which the same stop then releases. So only the
# observation of a request goes on to the next request.
ASKING_ONWARD = (("observing_request", NEXT_ASKED), ("inspecting_request", NEXT_LISTED)) + ONWARD
ASKING_ENDING = ASKING_ONWARD + (("stopped", ()),)
# Each reading that deals with a binding: the states it is read in, and how the stop
# goes on from it. Only a binding that is no longer held (released, or not listed) can
# end the stop in `stopped`.
DEALT_WITH = (("OK", RELEASABLE, ENDING), (OBSERVED, OBSERVING, ENDING),
              (NOT_LISTED, INSPECTING, ENDING),
              (REFUSED, RELEASABLE, ONWARD), (UNCERTAIN, RELEASABLE, ONWARD),
              (SILENT, RELEASABLE, ONWARD), (UNSENT, RELEASABLE, ONWARD),
              (STILL_UNCERTAIN, OBSERVING, ONWARD),
              # the observation of a request that brought no answer: only the wait on
              # its operation can say that it never ran
              (FOUND, ASKING, ASKING_ENDING), (NEVER_RAN, ASKING_BY_WAIT, ASKING_ENDING),
              (STILL_OPEN, ASKING, ASKING_ONWARD),
              # a binding found out of its exit class is held, and the request is not
              # settled: the stop can no longer end in `stopped`
              (MISFIT, ASKING, ASKING_ONWARD))

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
    # a request that brought no answer ends its goal, and is never sent again. One that
    # was started may have reached Heimdall: `failed` names it as uncertain, with the
    # operation it named, and a later stop observes it. One that was never started has
    # its fault where the code would be
    Row(SENDING, UNANSWERED, "none", "failed", UNKNOWN_CODE + ITS_REQUEST + NAMED_BY_IT),
    Row(SENDING, UNANSWERED, "none", "failed", UNKNOWN_CODE + ITS_REQUEST),
    Row(SENDING, NOT_STARTED, "none", "failed", (("code", "=not_started"),) + ITS_REQUEST),
    # a wait on the accepted operation of a request that brought no answer, or was never
    # started, ends the goal too: the request is uncertain, and `failed` names it with
    # that operation. A later stop observes it
    Row(TRACKED, UNANSWERED, "none", "failed", STILL_UNKNOWN + ITS_REQUEST),
    Row(TRACKED, NOT_STARTED, "none", "failed", STILL_UNKNOWN + ITS_REQUEST),
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
    # A release that was answered, refused, uncertain, left without an answer or not
    # sent, and an uncertain one observed to have happened, to be not listed or to be
    # still unknown, each go on as ONWARD says (one row for each way). So does the
    # observation of a request that brought no answer, as ASKING_ONWARD says
    *(Row(states, reading, "none", to, takes)
      for reading, states, onward in DEALT_WITH for to, takes in onward),
    # the operation of an uncertain release ended and says the release did not happen:
    # one new release, of that binding. Only the state that waits on an operation has
    # this row: nothing read from the list of bindings leads to a release
    Row(WAITING, NOT_RUN, "none", "releasing", (("binding_id", "state.binding_id"),)),
    # the exit class did not fit the answer to a call that is not about a release: stop
    # and report both
    Row(CALLING, MISMATCH, "none", "inconsistent", CODE + (("exit_code", "exit_code"),)),
)

# The exit class the CLI documents for every published code: a frozen copy of the code
# table (schemas/public-api/codes.json, `exit_code`; docs/api/local-protocol.md, "Exit
# classes": 0 success, 1 internal, 2 usage, 3 needs a person, 4 not allowed, 5
# unavailable for now, 6 conflict, 7 uncertain, 127 a launch that failed). It is the
# fallback: where discovery has read the installed binary's own table, that table's
# class for a code is the one checked (`documented_exit`).
EXIT_CLASSES = {
    "OK": 0, "ACCESS_READY": 0, "ACCEPTED": 0,
    "APPROVAL_REQUIRED": 3, "INTERACTION_REQUIRED": 3, "PROVIDER_LOCKED": 3,
    "CAPABILITY_UNAVAILABLE": 4, "POLICY_PAUSED": 4, "POLICY_CUTOFF": 4,
    "CREDENTIAL_EXPIRED": 4, "HOST_TRUST_CHANGED": 4, "DELEGATION_EXCEEDS_PARENT": 4,
    "OPERATION_CANCELLED": 4,
    "DESTINATION_UNREACHABLE": 5, "TIME_UNCERTAIN": 5, "UNSUPPORTED_CLIENT": 5,
    "SERVICE_UNAVAILABLE": 5, "STATE_UNAVAILABLE": 5, "BACKPRESSURE": 5,
    "REQUEST_CONFLICT": 6, "CONFIG_CONFLICT": 6, "REQUEST_EXPIRED": 6, "RESYNC_REQUIRED": 6,
    "DECISION_STALE": 6,
    "OUTCOME_UNKNOWN": 7,
    "USAGE_ERROR": 2, "SCHEMA_UNSUPPORTED": 2, "NOT_FOUND": 2,
    "INTERNAL_ERROR": 1,
    "LAUNCH_FAILED": 127,
}
# The answers whose documented class is not their code's own, whatever table gave that:
# the code, the `next.action` and one typed field with the value it must have (None
# stands for any), and the class.
Excepted = namedtuple("Excepted", "code action field value exit")
EXIT_EXCEPTIONS = (
    # Still pending after a bounded wait. H2 never asks asynchronously, so `ACCEPTED` is
    # never the success it is for a caller that does.
    Excepted("ACCEPTED", None, None, None, 5),
    # An observation that found its operation unfinished when the wait ran out.
    Excepted("OK", "observe", None, None, 5),
    # A launch refused because the program is not one that can be run.
    Excepted("LAUNCH_FAILED", None, "data.error.reason", "not_executable", 126),
)

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
    "observing_request": ("observe", None),
    "inspecting_request": ("work", None),
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


def member(value, values):
    """Whether a typed field of an answer has one of `values`. A field that is no plain
    word has none of them. Where `values` is a check, whether the field passes it."""
    if callable(values):
        return values(value)
    return isinstance(value, str) and value in values


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
    """The state a stop enters for the next thing it asks about: the first way of
    ASKING_ONWARD whose facts are there. A request that brought no answer comes before
    any binding."""
    for to, takes in ASKING_ONWARD:
        fields = {field: lookup(facts, path) for field, path in takes}
        if all(value is not None for value in fields.values()):
            return State(to, **fields)
    raise PlannerError("the stop has no binding to go on with")


def release_says(call, answer, fits, table=RELEASE_SAYS):
    """What an answer says about a release: the reading of the first row of
    RELEASE_SAYS that applies. `fits` is whether its exit class fits its code.
    `table` is the table read, where it is another with rows of the same kind."""
    for row in table:
        if (row.call == call and row.code in (None, answer.code)
                and row.action in (None, answer.action) and row.fits in (None, fits)
                and all(member(lookup(answer.facts, field), values)
                        for field, values in row.wants)):
            return row.reading
    raise PlannerError(f"no reading for the call {call}")


def request_says(call, answer, fits):
    """What an observation says about a request that brought no answer: the reading of
    the first row of REQUEST_SAYS that applies."""
    return release_says(call, answer, fits, REQUEST_SAYS)


def unmatched(state, reading):
    """No row applied: `failed` with the answer's code. An uncertain outcome still names
    its operation when one is known: the one being observed, else the one the answer names."""
    if reading.code == "OUTCOME_UNKNOWN":
        for operation in (state.fields.get("operation_id"), lookup(reading.facts, "next.operation_id"),
                          lookup(reading.facts, "operation_id")):
            if FIELD_CHECKS["operation_id"](operation):
                return State("failed", code=reading.code, operation_id=operation)
    return State("failed", code=reading.code)


def documented_exit(reading, installed=None):
    """The exit class documented for an answer, and what it is documented for. The
    class is None where none is documented: a code no table has.

    `installed` is the installed binary's code table as discovery read it (each code
    with the class its row gives), when it was read. Its class for a code is the one
    checked, and the frozen EXIT_CLASSES is the fallback. The command-specific
    exceptions (EXIT_EXCEPTIONS) come before both.

    An observation is one more exception: its class is that of the state its operation
    was found in (OPERATION_STATES), and only an operation that ended is observed in
    the class of its own code. One that ended without succeeding and names no code has
    no documented class here."""
    state = lookup(reading.facts, "observed.state")
    if state in OPERATION_STATES:
        stage = OPERATION_STATES[state]
        if stage.exit is not None:
            return stage.exit, f"an operation that is {state}"
        if not stage.succeeded and lookup(reading.facts, "data.code") is None:
            return None, reading.code
    for row in EXIT_EXCEPTIONS:
        if (row.code == reading.code and row.action in (None, reading.action)
                and (row.field is None or lookup(reading.facts, row.field) == row.value)):
            return row.exit, reading.code
    listed = (installed or {}).get(reading.code)
    if type(listed) is int and 0 <= listed <= 255:
        return listed, reading.code
    return EXIT_CLASSES.get(reading.code), reading.code


def check_exit(reading, installed=None):
    """Check the exit status of an answer's process against the class documented for the
    answer (`documented_exit`). Returns (reading, None) when they agree, and otherwise
    the planner's own reading of the mismatch with its account. An answer whose process
    still runs, or was ended by this harness, has no exit status to check. A code no
    table has has no row in TRANSITIONS either, and has no documented class to check:
    as a refused release it is recorded with the exit status it came with. An answer
    about a release that fails this check is read by RELEASE_SAYS, and never by the row
    for a mismatch."""
    documented, subject = documented_exit(reading, installed)
    if reading.exit is None or documented is None or reading.exit == documented:
        return reading, None
    facts = {"code": reading.code, "exit_code": reading.exit}
    return (Reading(MISMATCH, "none", None, facts, reading.exit),
            f"exit {reading.exit} does not fit {subject}: its documented exit class is {documented}")


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


def no_answer(fault, problem, output=None, status=None, record=None):
    """The NoAnswer for a call that brought no answer the harness can use. `fault` says
    why (FAULTS), `output` is what the call printed before it ended or was ended, and
    `status` is its exit status when it ended by itself. `record` is what the run
    records of a launch named before that: a binding, an operation.

    Its reading is the planner's own, and keeps what a first complete line of the
    output did say, from typed fields only: the code, and the operations and the
    binding the envelope names. An envelope that says `OUTCOME_UNKNOWN` is kept whole,
    as the uncertain answer it is. No other answer is taken from a process that did not
    end by itself with the one envelope asked for: not `OK`, and not a refusal."""
    why = {"fault": fault, "problem": problem}
    if record:
        why["record"] = dict(record)
    lines = output.split(b"\n") if isinstance(output, bytes) else []
    try:
        said = read_envelope(one_envelope(lines[0] + b"\n")) if len(lines) > 1 else None
    except PlannerError:
        said = None
    if said is None:
        return NoAnswer(problem, Reading(FAULTS[fault], "none", None, dict(why, code=None), status))
    if said.code == "OUTCOME_UNKNOWN":
        return NoAnswer(problem, said._replace(facts=dict(said.facts, **why), exit=status))
    facts = dict(why, code=said.code, operation_id=said.facts["operation_id"],
                 next={"operation_id": lookup(said.facts, "next.operation_id"),
                       "binding_id": lookup(said.facts, "next.binding_id")})
    return NoAnswer(problem, Reading(FAULTS[fault], "none", None, facts, status))


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
    """An observation, read by the typed `state` of the operation's view. The facts gain
    `observed.state` when the view is in a state OPERATION_STATES has. The view's own
    code is the answer's code only in a state that says the operation is over (OVER):
    whatever else the view of an operation that is still going carries, it is read as
    unfinished."""
    reading = read_envelope(envelope)
    if reading.code != "OK":
        return reading
    view = reading.facts["data"]
    require(view.get("operation_id") == operation_id, "the answer is about another operation")
    state, code = view.get("state"), view.get("code")
    if not member(state, tuple(OPERATION_STATES)):
        return reading
    reading = reading._replace(facts=dict(reading.facts, observed={"state": state}))
    if code is None or state not in OVER:
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


# A creation time as the list of bindings gives it: an RFC 3339 instant in UTC, to the
# nanosecond at most (the runtime's own wall clock).
INSTANT = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z")


def instant(value):
    """An instant of the list of bindings in nanoseconds since the epoch, or None where
    the value is not one (no leap second)."""
    found = INSTANT.fullmatch(value) if isinstance(value, str) else None
    if found is None:
        return None
    year, month, day, hour, minute, second = map(int, found.groups()[:6])
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    if not (1 <= month <= 12 and hour < 24 and minute < 60 and second < 60
            and 1 <= day <= (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)[month - 1]):
        return None
    # Days since 1970-01-01 in the proleptic Gregorian calendar, the year starting in March.
    shifted = year - (month <= 2)
    era, of_era = divmod(shifted, 400)
    day_of_year = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    day_of_era = of_era * 365 + of_era // 4 - of_era // 100 + day_of_year
    days = era * 146097 + day_of_era - 719468
    seconds = ((days * 24 + hour) * 60 + minute) * 60 + second
    return seconds * 10**9 + int((found.group(7) or "0").ljust(9, "0"))


def later(value, sent):
    """Whether an instant of the list is later than `sent`, the moment this planner sent
    a request (nanoseconds since the epoch, on the same host's wall clock)."""
    made = instant(value)
    return type(sent) is int and made is not None and made > sent


# Every typed field of an entry of the list of bindings that ties the binding to one
# request, with the check it must pass against what was asked (ruled 2026-11-23). The
# list carries no request ID and no field that names a caller: it is this caller's own
# list. `grant_id` and `profile_revision` tie a binding to no request, and the entry
# must be in the state `active` to be one to release.
ATTRIBUTION = (
    ("work_id", lambda value, request: value == request["work_id"]),
    ("profile", lambda value, request: value == request["profile"]),
    # made after the request was sent: an older binding is another request's
    ("created_at", lambda value, request: later(value, request.get("sent_at"))),
)


def read_work(envelope, request):
    """The complete list of this caller's bindings, reduced to what it says of one
    request (its `work_id` and `profile`, and `sent_at`, the moment it was sent). The
    facts gain `work.active`, the bindings it names for that work in the state `active`,
    and `work.matching`, those of them that pass every check of ATTRIBUTION, each in the
    list's order. An answer that is not `OK` with a list of entries gains nothing, and
    so does a list in which such an entry has no usable binding ID, or that names one
    binding twice with different ties: none says anything of the request."""
    reading = read_envelope(envelope)
    listed = reading.facts["data"].get("bindings")
    if (reading.code != "OK" or not isinstance(listed, list)
            or not all(isinstance(entry, dict) for entry in listed)):
        return reading
    active, matching = [], []
    for entry in listed:
        if entry.get("work_id") == request["work_id"] and entry.get("state") == "active":
            binding = entry.get("binding_id")
            if not FIELD_CHECKS["binding_id"](binding):
                return reading
            tied = all(check(entry.get(field), request) for field, check in ATTRIBUTION)
            if binding in active:
                if tied != (binding in matching):
                    return reading
                continue
            active.append(binding)
            if tied:
                matching.append(binding)
    return reading._replace(facts=dict(reading.facts, work={"active": active, "matching": matching}))


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
        """Whether the child wrote a line before its output ended. None when the wait
        ran out first: the child is then still there, and has said nothing."""
        try:
            return self.lines.get(timeout=seconds) is not None
        except queue.Empty:
            return None

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
        # Every binding it was ever given, in the order it first held them.
        self.ever_held = []
        # Every call this planner made about the release of a binding, oldest first:
        # the binding, who called (`by`: a stop goal, or the close), the outcome, the
        # answer's code and the exit status of its process. An observation also says
        # what it observed.
        self.attempts = []
        # How many of them came before the stop in progress. A binding that stop was
        # refused, or left uncertain, is set aside: the stop does not ask about it again.
        self.stop_began = 0
        # Each held binding whose release was answered uncertainly, or was started and
        # brought no answer, and has not been observed to an end since: the request ID
        # of that release (none today), and the operation its answer named, when it
        # named one. Its release is not sent again while it is here.
        self.uncertain = {}
        self.by = "stop"
        # Each request (`access ensure`, `run`) that was started, brought no answer and
        # named no binding, and has not been settled by an observation since: what was
        # asked (the command, the profile and the work), under its request ID, and the
        # operation it named, when it named one. So is one answered whose operation was
        # left open (KEPT, TRACKED). It is never sent again.
        self.requests = {}
        # The moment each of them was sent (nanoseconds since the epoch), under its
        # request ID: a binding the list shows for it must have been made later.
        self.sent_at = {}
        # The request sent last: its call, request ID and the moment it was sent, and the
        # code and exit status of its answer once there is one.
        self.sent = {}
        # Every call this planner made that is about such a request, oldest first: the
        # request itself, and each observation of it. The goal that made the call is
        # its `by` (`close` for the close).
        self.asked = []
        # How many of them came before the stop in progress: that stop observes each
        # uncertain request once.
        self.asked_began = 0
        self.goal = None

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
        """Make one call and reduce its answer to a Reading that carries its exit status.

        A call that brings no answer raises NoAnswer, which says whether the call was
        started at all. One that was started may have reached Heimdall, whatever
        became of its process afterwards: what it printed before it ran past its time
        limit, or beside an answer that cannot be read, is kept (`no_answer`)."""
        try:
            env = launch_environment(self.root, self.given)
        except (PlannerError, OSError) as error:
            problem = str(error) if isinstance(error, PlannerError) else "the CLI could not be started"
            raise no_answer("not_started", problem) from None
        values = dict(self.work or {}, observe_ms=OBSERVE_MS, **self.state.fields)
        kind = self.calls[name]["answer"]
        if kind == "launch":
            return self.launch(name, values, goal, env, metrics)
        argv = [*self.command, *BASE_FLAGS, *self.arguments(name, values, goal)]
        metrics["calls"] += 1
        self.sending(name)
        try:
            done = subprocess.run(argv, env=env, cwd=self.root, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  timeout=CALL_SECONDS)
        except subprocess.TimeoutExpired as late:
            raise no_answer("timed_out", "a CLI call ran past its time limit", late.stdout) from None
        except OSError:
            raise no_answer("not_started", "the CLI could not be started") from None
        try:
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
            elif kind == "work":
                reading = read_work(envelope, dict(self.requests[values["request_id"]],
                                                   sent_at=self.sent_at.get(values["request_id"])))
            else:
                reading = read_envelope(envelope)
        except PlannerError as error:
            raise no_answer("unreadable", str(error), done.stdout, done.returncode) from None
        return reading._replace(exit=done.returncode)

    def sending(self, name):
        """Note the moment a request is sent, just before its process starts."""
        if name in REQUESTS:
            self.sent = {"call": name, "request_id": self.work["request_id"],
                         "sent_at": time.time_ns()}

    def asked_for(self):
        """What the request in progress asks: the command, the profile and the work."""
        return {"call": REQUESTS[GOALS[self.goal]["first"]], "profile": self.work["profile"],
                "work_id": self.work["work_id"]}

    def remember(self, request_id, request):
        """Keep a request whose outcome is unknown, with the moment it was sent."""
        self.requests[request_id] = request
        if self.sent.get("request_id") == request_id:
            self.sent_at[request_id] = self.sent["sent_at"]

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

    def open_requests(self):
        """The uncertain requests the stop in progress may still observe, oldest first:
        each is observed once in a stop."""
        asked = {attempt["request_id"] for attempt in self.asked[self.asked_began:]
                 if "observed" in attempt}
        return [request_id for request_id in self.requests if request_id not in asked]

    def unreleased(self):
        """The first attempt of the stop in progress that settled nothing: an
        observation that left a request uncertain, else the first attempt that left its
        binding held. A stop observes its requests first."""
        for attempt in self.asked[self.asked_began:]:
            if "observed" in attempt and attempt["request_id"] in self.requests:
                return attempt
        return next((attempt for attempt in self.attempts[self.stop_began:]
                     if attempt["outcome"] in SET_ASIDE), None)

    def release_facts(self, binding_id):
        """The planner's own facts for an answer about the release of `binding_id`: the
        next binding the stop may ask about beside this one (`approach`), when there is
        one; and the first binding this stop did not release (`unreleased.*`), when
        there is one. An uncertain one is named with the code `OUTCOME_UNKNOWN`. One
        whose release was not sent has no code: its fault stands where the code would,
        as a launch's run record does.

        They also name the next uncertain request the stop may observe (`request.*`),
        when there is one. Where the first thing the stop did not settle is a request,
        `unreleased.*` names that request and no binding."""
        others = [held for held in self.releasable() if held != binding_id]
        facts = self.approach(others[-1]) if others else {"held": {}, "uncertain": {}}
        facts["request"] = {}
        for request_id in self.open_requests()[:1]:
            facts["request"] = dict(self.requests[request_id], request_id=request_id)
        facts["unreleased"] = {}
        first = self.unreleased()
        if first is not None:
            uncertain = first["outcome"] in UNKNOWN
            facts["unreleased"] = {"code": "OUTCOME_UNKNOWN" if uncertain
                                   else first["code"] or first.get("fault")}
            for field in ("binding_id", "exit_code", "operation_id", "request_id"):
                if field in first:
                    facts["unreleased"][field] = first[field]
        return facts

    def settle(self, call, answer, problem, binding_id):
        """Read an answer about the release of `binding_id` (RELEASE_SAYS), record the
        attempt, and return the planner's own reading of it for the table. `problem`
        says how the answer's exit class did not fit, when it did not.

        A binding that was released leaves `held`, and so does one the complete list
        of bindings does not name. Any other stays. An uncertain release is remembered
        with the operation its answer named, so that a later stop observes it and
        does not send it again. So is a release that was started and brought no
        answer, with the operation named by whatever it printed.

        Where the call brought no answer, `answer` is the planner's own (`no_answer`):
        the attempt records the fault, and the code only of what was printed."""
        says = release_says(call, answer, problem is None)
        attempt = {"binding_id": binding_id, "by": self.by, "outcome": OUTCOMES[says],
                   "code": answer.code if _word(answer.code) else answer.facts.get("code"),
                   "exit_code": answer.exit}
        if call in OBSERVED_BY:
            attempt["observed"] = OBSERVED_BY[call]
        if lookup(answer.facts, "binding.state") is not None:
            attempt["state"] = answer.facts["binding"]["state"]
        if "fault" in answer.facts:
            attempt.update(fault=answer.facts["fault"], detail=answer.facts["problem"])
        if problem is not None:
            # Heimdall's own table gives each code one exit class.
            attempt.update(inconsistent=True, detail=f"{problem}; a probable product defect")
        if says in REMEMBERED:  # the release's own answer, or none
            # The operation the answer's `next` names, else the envelope's own.
            self.uncertain[binding_id] = {"request_id": RELEASE_REQUEST_ID}
            for operation in (answer.facts.get("operation_id"),
                              lookup(answer.facts, "next.operation_id")):
                if FIELD_CHECKS["operation_id"](operation):
                    self.uncertain[binding_id]["operation_id"] = operation
        if OUTCOMES[says] in UNKNOWN:  # it names the same request and operation
            attempt.update(self.uncertain.get(binding_id, {}))
        else:
            self.uncertain.pop(binding_id, None)
        if OUTCOMES[says] in NOT_HELD:
            self.held = [held for held in self.held if held != binding_id]
        self.attempts.append(attempt)
        return Reading(says, "none", answer.effect,
                       dict(answer.facts, **self.release_facts(binding_id)), answer.exit)

    def unanswered(self, call, answer):
        """Record a request that brought no answer (`answer` is the planner's own, from
        `no_answer`), and return the planner's reading of it for the table: its fault
        stands where the code would.

        A request that was never started was not sent, and nothing is remembered. One
        that was started may have reached Heimdall. A binding it named before it
        stopped is held from here on: a complete envelope or run record is kept. Where
        it named none, the request is remembered with its request ID and the operation
        it named, so that a later stop observes what became of it. It is never sent
        again: every goal has a request ID of its own."""
        fault = answer.facts["fault"]
        request_id = self.work["request_id"]
        request = {"call": REQUESTS[call], "profile": self.work["profile"],
                   "work_id": self.work["work_id"]}
        named = {}
        # The operation the answer's `next` names, else the envelope's own, else the
        # run record's.
        for operation in (lookup(answer.facts, "record.operation_id"),
                          answer.facts.get("operation_id"),
                          lookup(answer.facts, "next.operation_id")):
            if FIELD_CHECKS["operation_id"](operation):
                named["operation_id"] = operation
        bindings = []
        for binding in (lookup(answer.facts, "next.binding_id"),
                        lookup(answer.facts, "record.binding_id")):
            if FIELD_CHECKS["binding_id"](binding) and binding not in bindings:
                bindings.append(binding)
        attempt = dict(request, request_id=request_id, by=self.goal,
                       outcome=REQUEST_OUTCOMES[FAULTS[fault]], code=answer.facts.get("code"),
                       exit_code=answer.exit, fault=fault, detail=answer.facts["problem"], **named)
        if bindings:
            attempt["bindings"] = bindings
            for binding in bindings:
                self.hold(binding)
        elif FAULTS[fault] == UNANSWERED:
            self.remember(request_id, dict(request, **named))
        self.asked.append(attempt)
        facts = dict(answer.facts, request=dict(named, request_id=request_id))
        return Reading(FAULTS[fault], "none", None, facts, answer.exit)

    def untracked(self, answer):
        """Record a wait on the accepted operation of the request in progress (TRACKED)
        that brought no answer (`answer` is the planner's own, from `no_answer`), and
        return the planner's reading of it for the table: its fault stands where the
        code would.

        The request was answered, and its operation may yet make a binding. It is
        remembered with that operation, so that a later stop observes it, and it is
        never sent again. The attempt is an observation that did not say what became of
        the request: `still_unknown`, with the fault."""
        request_id, operation = self.work["request_id"], self.state.fields["operation_id"]
        request = self.asked_for()
        attempt = dict(request, request_id=request_id, by=self.goal,
                       outcome=REQUEST_OUTCOMES[STILL_OPEN],
                       code=answer.code if _word(answer.code) else answer.facts.get("code"),
                       exit_code=answer.exit, observed=REQUEST_OBSERVED_BY["observe"],
                       fault=answer.facts["fault"], detail=answer.facts["problem"],
                       operation_id=operation)
        self.remember(request_id, dict(request, operation_id=operation))
        self.asked.append(attempt)
        facts = dict(answer.facts, request={"request_id": request_id, "operation_id": operation})
        return Reading(FAULTS[answer.facts["fault"]], "none", None, facts, answer.exit)

    def unresolved(self):
        """The goal of a request ended in a state of KEPT: the request was answered, and
        its operation was still open. Record it with the outcome KEPT names, the code and
        exit status of its answer, and that operation, and remember it, so that a later
        stop observes it. It is never sent again."""
        request_id, operation = self.work["request_id"], self.state.fields["operation_id"]
        request = self.asked_for()
        answered = self.sent if self.sent.get("request_id") == request_id else {}
        self.asked.append(dict(request, request_id=request_id, by=self.goal,
                               outcome=KEPT[self.state.name], code=answered.get("code"),
                               exit_code=answered.get("exit_code"), operation_id=operation))
        self.remember(request_id, dict(request, operation_id=operation))

    def conclude(self, call, answer, problem, request_id):
        """Read an observation of the uncertain request `request_id` (REQUEST_SAYS),
        record the attempt, and return the planner's own reading of it for the table.
        `problem` says how the answer's exit class did not fit, when it did not.

        A binding the observation shows is held from here on, so that the stop in
        progress releases it like any other: the one the request's operation says it
        made, or the one binding the complete list names `active` that can be the
        request's own (ATTRIBUTION) and that this planner was never given. Where the list
        names more than one such binding, none is held. The request is then settled, and
        so is one whose operation says that it never ran. A binding shown in another exit
        class is held too, and the request stays uncertain (MISFIT). Any other stays
        uncertain, and is observed again by a later stop. A binding this planner was ever
        given is never held again from an observation."""
        request = self.requests[request_id]
        facts = dict(answer.facts)
        listed = lookup(facts, "work.active")
        # A binding this planner was ever given is the answer's that gave it.
        new = [binding for binding in lookup(facts, "work.matching") or []
               if binding not in self.ever_held]
        if listed is not None:  # the planner's own word on what the list names
            facts["work"] = dict(facts["work"], found=SEVERAL if len(new) > 1 else NEW if new
                                 else NONE_NEW)
        says = request_says(call, answer._replace(facts=facts), problem is None)
        attempt = dict(request, request_id=request_id, by="close" if self.by == "close" else self.goal,
                       outcome=REQUEST_OUTCOMES[says],
                       code=answer.code if _word(answer.code) else answer.facts.get("code"),
                       exit_code=answer.exit, observed=REQUEST_OBSERVED_BY[call])
        if listed is not None:
            attempt.update(listed=listed, candidates=new)
        if "fault" in answer.facts:
            attempt.update(fault=answer.facts["fault"], detail=answer.facts["problem"])
        if problem is not None:
            attempt.update(inconsistent=True, detail=f"{problem}; a probable product defect")
        if says in GIVING:
            named = new if call == "work" else [lookup(facts, "data.result.binding_id")]
            given = [binding for binding in named if binding not in self.ever_held]
            if given:
                attempt["bindings"] = given
            for binding in given:
                self.hold(binding)
        if says in SETTLED:
            del self.requests[request_id]
            self.sent_at.pop(request_id, None)
        self.asked.append(attempt)
        return Reading(says, "none", answer.effect, dict(facts, **self.release_facts(None)),
                       answer.exit)

    def recorded(self, outcome, since=0):
        """The attempts from `since` on that had this outcome, as a record lists them."""
        return [{key: value for key, value in attempt.items() if key not in ("by", "outcome")}
                for attempt in self.attempts[since:] if attempt["outcome"] == outcome]

    def recorded_requests(self, outcome, since=0):
        """The same for the attempts that are about requests."""
        return [{key: value for key, value in attempt.items() if key not in ("by", "outcome")}
                for attempt in self.asked[since:] if attempt["outcome"] == outcome]

    def by_request(self):
        """Each request that brought no answer: what was asked, whether it is still
        uncertain, and every attempt about it in order."""
        about = ("request_id", "call", "profile", "work_id")
        named = {}
        for attempt in self.asked:
            entry = named.setdefault(attempt["request_id"], dict(
                {key: attempt[key] for key in about[1:]},
                uncertain=attempt["request_id"] in self.requests, attempts=[]))
            entry["attempts"].append({key: value for key, value in attempt.items()
                                      if key not in about})
        return named

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
        if binding_id not in self.ever_held:
            self.ever_held.append(binding_id)

    def launch(self, name, values, goal, env, metrics):
        """`run`: start the child and read the launch's run record, or its refusal.

        A launch that brings neither raises NoAnswer, like any call: the CLI could not
        be started; the child wrote no line before the time limit; or what the process
        left is neither a run record of a launch nor one envelope."""
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
        self.sending(name)
        try:
            process = subprocess.Popen(argv, env=env, cwd=self.root, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError:
            raise no_answer("not_started", "the CLI could not be started") from None
        child = Child(process)
        up = child.first_line(LAUNCH_SECONDS)
        # A child that wrote no line is ended before its records are read, so that
        # what it wrote until then is whole.
        status = None if up else child.end(1)
        records, unread = [], None
        try:
            try:
                records = read_run_records(meta.read_text(encoding="utf-8")) if meta.is_file() else []
            except (OSError, UnicodeError):
                unread = "the run records could not be read"
            except PlannerError as error:
                unread = str(error)
            types = [record["type"] for record in records]
            for record in records:  # a binding a record names is held, whatever became of the launch
                if FIELD_CHECKS["binding_id"](record.get("binding_id")):
                    self.hold(record["binding_id"])
            if up and types == ["launching"]:
                require(records[0].get("pid") == process.pid, "the run record names another process")
                self.child = child
                return Reading("launching", "none", None, {"record": records[0]})
        finally:
            if self.child is None and up:
                status = child.end(1)
            if meta.is_file():
                meta.unlink()
        # Not launched. What the records named before that is kept: a binding, an operation.
        errors, kept = bytes(child.errors), {}
        for record in records:
            for field in ("binding_id", "operation_id"):
                if FIELD_CHECKS[field](record.get(field)):
                    kept.setdefault(field, record[field])
        if up is None:  # the wait ran out, and this harness ended the process
            raise no_answer("timed_out", "a CLI call ran past its time limit", errors, record=kept)
        if unread is not None:
            raise no_answer("unreadable", unread, errors, status, kept)
        # The child ended without a word after a launch its record tells of: that record
        # is the answer, and the binding it names is held.
        require("launching" not in types or "prelaunch_failed" in types,
                f"the child wrote no line (exit {status})")
        try:  # a refusal is one envelope on stderr
            return read_envelope(one_envelope(errors))._replace(exit=status)
        except PlannerError as error:
            raise no_answer("unreadable", str(error), errors, status, kept) from None

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
                           and self.state.fields["binding_id"] in self.releasable()
                           or self.state.name in ASKING
                           and self.state.fields["request_id"] in self.open_requests())
            if new:
                self.stop_began, self.asked_began = len(self.attempts), len(self.asked)
            candidates = self.releasable()
            # A request that brought no answer is observed before any binding is asked
            # about: it may give a binding, which this stop then releases.
            if self.open_requests():
                self.state = entering(self.release_facts(None))
                return
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
        self.goal = goal["goal"]
        self.begin(goal, spec, new)
        expected = goal.get("expect_refusal")
        call = spec["first"]
        if self.state.name in OBSERVING + ASKING:  # a stop that begins at an observation
            call = FOLLOW[self.state.name][0]
        for _ in range(MAX_STEPS):
            before = self.state
            about_release = call == "release" or before.name in OBSERVING
            about_request = before.name in ASKING
            tracked = before.name in TRACKED
            try:
                answer = self.invoke(call, goal, metrics)
            except NoAnswer as silence:
                if not (about_release or about_request or call in REQUESTS or tracked):
                    raise
                # No answer to a call about a release, to a request, or to the wait on
                # the accepted operation of a request: the planner's own answer stands
                # where it would be, and is read and recorded like any other. A release
                # or a request that may have been sent is never forgotten.
                answer = silence.reading
            unanswered = (call in REQUESTS or tracked) and "fault" in answer.facts
            if unanswered:
                answer = self.unanswered(call, answer) if call in REQUESTS else self.untracked(answer)
            elif call in REQUESTS:  # the answer to the request, as a later record names it
                self.sent.update(code=answer.code, exit_code=answer.exit)
            if answer.action in INVALID_REQUEST_ACTIONS:
                metrics["invalid_retries"] += 1
            reading, problem = check_exit(answer, self.installed_codes)
            if about_release:
                # An answer about a release is read by RELEASE_SAYS, its exit class
                # with it, and the table gets the planner's own reading. It never ends
                # the stop where it stands: the other bindings are still asked about.
                answer = reading = self.settle(call, answer, problem, before.fields["binding_id"])
                problem = None
            elif about_request:
                # The observation of an uncertain request is read by REQUEST_SAYS in
                # the same way, and the stop goes on.
                answer = reading = self.conclude(call, answer, problem, before.fields["request_id"])
                problem = None
            elif unanswered:  # the goal ends here, and says what went wrong with the call
                problem = answer.facts["problem"]
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
                if about_release or about_request:
                    # The stop ends: it names the first thing it did not settle.
                    problem = self.unreleased().get("detail")
                require(expected == after.fields["code"] and not unanswered,
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
            if self.state.name in KEPT:  # the request's operation may yet make a binding
                self.unresolved()
            raise PlannerError(f"the goal was not met within the step limit: {self.state!r}")
        raise PlannerError("the goal was not met within the step limit")

    def close(self):
        """Release every binding still held, then end a child that is still held, by its
        own handle. Returns the bindings released here and those still held. A binding
        Heimdall refused to release, or whose release is still uncertain, is still
        held, and `attempts` names it. A binding the list of bindings did not name is
        in neither: it is not held, and it was not observed to be released.

        The whole of it is one stop of its own, made in rounds that are each bounded
        like any goal: it asks about every held binding once, whatever an earlier stop
        was answered, and a binding it does not release is not asked about again in a
        later round. An uncertain release of an earlier stop is observed, not sent
        again. One of its own is left as it is: the close does not observe it.

        Every call about a binding is an attempt, a call that brought no answer
        included, so one binding's failure never keeps the others from being asked
        about. Each round but the last leaves fewer bindings to ask about, and the
        whole is bounded too. A round that makes no attempt at all ends it.

        A request that brought no answer is observed first, once, and never sent
        again. A binding that observation shows is held, and released here like any
        other. A request it cannot settle stays uncertain, and `by_request` names it."""
        before, began = set(self.held), len(self.attempts)
        requests, round_ = len(self.requests), 0
        self.by = "close"
        try:
            # At most two calls for a binding, and one for a request. `before` grows by
            # the bindings the requests are observed to have made.
            while round_ < 2 * len(before) + requests:
                left = len(self.attempts) + len(self.asked)
                try:
                    self.pursue({"goal": "stop"}, new_metrics(), new=round_ == 0)
                except (PlannerError, OSError):
                    pass
                before.update(self.held, (attempt["binding_id"] for attempt in self.attempts[began:]))
                round_ += 1
                if (left == len(self.attempts) + len(self.asked)
                        or not (self.releasable() or self.open_requests())):
                    break
        finally:
            self.by = "stop"
        if self.child is not None:
            child, self.child = self.child, None
            child.end(1)
        released = {attempt["binding_id"] for attempt in self.attempts[began:]
                    if attempt["outcome"] == "released"}
        return {"released": [binding for binding in self.ever_held
                             if binding in released and binding not in self.held],
                "held": list(self.held)}


# --------------------------------------------------------------------------------------
# Goals and records
# --------------------------------------------------------------------------------------

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
    asked = len(planner.asked)
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
                  **{name: planner.recorded(outcome, attempted)
                     for name, outcome in RECORDED.items()},
                  **{name: planner.recorded_requests(outcome, asked)
                     for name, outcome in REQUEST_RECORDED.items()})
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
    # close, with all its attempts in order: each fails the run. That includes a binding
    # found not listed, which is no longer held.
    unreleased = planner.by_binding()
    # Every request that brought no answer, with the observations of it: each fails the
    # run too, whatever an observation then made of it.
    unanswered = planner.by_request()
    print(json.dumps({"harness": "H2", "call_set": CALL_SET_SOURCE, "tasks": tasks,
                      "close": closing, "release_attempts": unreleased,
                      "request_attempts": unanswered}))
    return int(any(not task["success"] for task in tasks) or bool(closing["held"])
               or bool(unreleased) or bool(unanswered))


if __name__ == "__main__":
    sys.exit(main())
