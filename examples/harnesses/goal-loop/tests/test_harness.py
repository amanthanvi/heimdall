import ast
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parents[1] / "harness.py"
_spec = importlib.util.spec_from_file_location("heimdall_goal_loop", SOURCE)
h2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(h2)

SAMPLES = {
    "operation_id": "op_sample", "decision_ref": "dec_sample", "binding_id": "binding_sample",
    "provider": "fixture_provider", "kind": "provider_unlock", "pid": 4242, "code": "SAMPLE",
    "exit_code": 9, "request_id": "request-sample", "work_id": "work-sample",
}

# A stand-in `heimdall`: `stub.py [MODE] --json --non-interactive <command...>`. It checks
# the launch environment, logs each command, and answers from fixed data. For `run` it is
# the child itself: it writes the run record, prints one line and waits for its input to end.
# Mode `exit:CODE=N` ends every answer whose envelope code is CODE with exit N instead of
# the documented class, the envelope unchanged.
# Mode `refuse:A,B` refuses the release of bindings A and B, and `refuse:*` every release:
# the caller does not own the binding. `refuse-unknown:` answers that there is no such
# binding, `refuse-novel:` with a code no table has, and `refuse-exit-0:` as `refuse:`
# does but in the wrong exit class. `refuse-unavailable-exit-0:` answers that the service
# is unavailable, with exit 0 (M07-W5-R03's probe). `refuse-installed:` answers with
# `ONLY_INSTALLED`, a code that only this stub's own code table lists (exit class 6),
# and exits 1.
# Mode `uncertain:NAMES:MEANS:SAYS[:EXIT]` answers the first release of each binding in
# NAMES with `OUTCOME_UNKNOWN` (exit 7, or EXIT). MEANS is how that answer names its
# operation: `operation` (in `next`), `own` (the envelope's own only), `bindings` (none).
# SAYS is what an observation then says. Of the operation: `released`, `never-ran` (it
# failed with effect `none`), `partial` (it ended with a partial effect), `unknown`,
# `unfinished`, `missing` (there is no such operation), `wrong-exit` (ended, but in the
# wrong exit class), `contradictory` (M07-W5-R02's probe: still running, yet answered
# `OK` with no next action and exit 0), `active-refusal` (still running, yet with a
# refusal's code, no effect and that code's exit class), `ended-badly` (it failed, yet
# its own code is `OK`). Of the list of bindings, for each binding in NAMES: `active`,
# `released`, `absent` (not listed), `odd` (a state no table has), `twice` (listed in
# two states), `unknown` (the list cannot be read), `wrong-exit` (as `absent`, in the
# wrong exit class). The list always names one other binding, `active`.
# A mode may begin `sleep:WHAT:`, and what follows is the mode as above. The process of a
# call then stays instead of ending, until the harness ends it (M07-W5-R01's probes).
# WHAT is `answered` (the first release of each binding: it prints its answer, then
# stays), `release` (every release: it stays without a word) or `always` (every release
# and every observation: it stays without a word). For a launch, WHAT is `run` (it stays
# without a record and without a line) or `run-recorded` (it writes its run record,
# then stays without a line).
# Three profiles are requests that bring no answer (M07 W6b). `late`: `access ensure`
# prints its answer, then stays. `silent`: it stays without a word. `garbled`: it prints
# something that is no envelope and ends (and so does a launch, on stderr, with exit 1).
# Mode `work:NAMES:SAYS` is what the list of bindings then says of the work `work-1`: it
# names each binding in NAMES for that work, `active`, `released` or `odd` (a state no
# table has); `none` (it names no binding for that work); `unknown` (the list cannot be
# read); `wrong-exit` (as `active`, in the wrong exit class).
STUB = r'''
import json
import os
from pathlib import Path
import sys
import time

args = sys.argv[1:]
mode = "normal" if args[0] == "--json" else args.pop(0)
sleeps = None
stays = False  # this call prints its answer, then stays
if mode.startswith("sleep:"):
    _, sleeps, mode = mode.split(":", 2)
assert args[:2] == ["--json", "--non-interactive"], args
args = args[2:]
uncertain = (dict(zip(("names", "means", "says", "exit"), mode.split(":")[1:]))
             if mode.startswith("uncertain:") else None)
root = Path.cwd()
for key, directory in (("HOME", "acct"), ("HEIMDALL_HOME", "hm"), ("HEIMDALL_TEST_SSH_HOME", "sshh")):
    assert Path(os.environ[key]).resolve() == root / directory, key
assert "SSH_AUTH_SOCK" not in os.environ and "H2_TEST_FOREIGN_ENV" not in os.environ
assert os.environ["HEIMDALL_TEST_SECRET_STORE"] == "scratch"
assert os.environ["HEIMDALL_TEST_MGMT_STORE"].startswith("fixture-file:")
assert Path(os.environ["HEIMDALL_TEST_MGMT_STORE"][len("fixture-file:"):]).resolve() == root / "mgmt-store"
assert Path(os.environ["HEIMDALL_TEST_IROH_KEY_STORE"]).resolve() == root / "iroh-key-store"
assert sorted(key for key in os.environ if key.startswith("HEIMDALL_")) == [
    "HEIMDALL_HOME", "HEIMDALL_TEST_IROH_KEY_STORE", "HEIMDALL_TEST_MGMT_STORE",
    "HEIMDALL_TEST_SECRET_STORE", "HEIMDALL_TEST_SSH_HOME",
]
if os.name == "nt":
    windows = Path(os.environ["SystemRoot"])
    system = windows / "System32"
    assert os.environ["PATH"].split(";") == list(map(str, (system / "OpenSSH", system, windows)))
    for name in ("USERPROFILE", "ProgramData", "ALLUSERSPROFILE",
                 "APPDATA", "LOCALAPPDATA", "TEMP", "TMP"):
        assert os.environ[name] == os.environ["HOME"]
else:
    assert os.environ["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin"
with (root / "calls.jsonl").open("a", encoding="utf-8") as log:
    print(json.dumps(args), file=log)

OP, BINDING, DECISION = "op_fixture", "binding_fixture", "dec_fixture"
SECOND = "binding_second"
CODES = ["OK", "ACCESS_READY", "ACCEPTED", "APPROVAL_REQUIRED", "INTERACTION_REQUIRED",
         "PROVIDER_LOCKED", "CAPABILITY_UNAVAILABLE", "POLICY_PAUSED", "POLICY_CUTOFF",
         "OPERATION_CANCELLED", "REQUEST_CONFLICT", "OUTCOME_UNKNOWN", "NOT_FOUND"]
# Prose that says the opposite of the code: a caller that read it would go wrong.
LIES = {"ACCESS_READY": "APPROVAL_REQUIRED: denied, nothing is ready, ask again",
        "ACCEPTED": "ACCESS_READY: finished, use the binding now",
        "INTERACTION_REQUIRED": "ACCESS_READY: approved already, no decision is pending",
        "CAPABILITY_UNAVAILABLE": "ACCESS_READY: granted", "OK": "FAILED: unknown code"}
UNFINISHED = {"still-pending": 1, "never": 1 << 30}


def count(name):
    path = root / ("count-" + name)
    seen = int(path.read_text()) if path.exists() else 0
    path.write_text(str(seen + 1))
    return seen


def emit(code, exit_code=0, data=None, next=None, stream=sys.stdout, **fields):
    record = dict(schema_version="1", code=code, data=data, next=next, **fields)
    if mode == "lying":
        record["message"] = LIES.get(code, "ACCESS_READY")
        if isinstance(data, dict) and "error" in data:
            data["error"]["message"] = record["message"]
    print(json.dumps(record), file=stream, flush=True)
    if sleeps == "answered" and args[:2] == ["access", "release"] and count("slept-" + args[2]) == 0:
        time.sleep(60)
    if stays:
        time.sleep(60)
    if mode.startswith("exit:") and mode[5:].split("=")[0] == code:
        exit_code = int(mode.split("=")[1])
    sys.exit(exit_code)


def refuse(code, action, exit_code, effect="none", stream=sys.stdout, **next_fields):
    following = dict(action=action, **next_fields)
    emit(code, exit_code, {"error": {"code": code, "effect_status": effect, "next": following}},
         following, stream, state="failed", operation_id=OP)


def ready():
    emit("ACCESS_READY", 0, {"binding_id": BINDING}, {"action": "use_binding", "binding_id": BINDING},
         state="succeeded", operation_id=OP)


def view(code, state, effect, result, following=None, exit_code=0):
    operation = "op_other" if mode == "other-operation" else OP
    emit("OK", exit_code, {"operation_id": operation, "code": code, "state": state,
                           "effect_status": effect, "result": result}, following,
         state=state, operation_id=OP)


if args == ["schema", "show", "codes"]:
    listed = [code for code in CODES if not (mode == "old-binary" and code == "PROVIDER_LOCKED")]
    # No row gives an exit class but the last: a code no frozen table has.
    emit("OK", 0, {"codes": [{"code": code} for code in listed]
                   + [{"code": "ONLY_INSTALLED", "exit_code": 6}]}, state="succeeded")
elif args[:2] == ["access", "ensure"]:
    assert args[2] == "--profile" and args[4] == "--work-id" and args[6] == "--request-id", args
    profile, options = args[3], args[8:]
    if profile == "silent":
        time.sleep(60)
    if profile == "garbled":
        print("this is no envelope", flush=True)
        sys.exit(0)
    stays = profile == "late"
    if profile == "novel":
        emit("SOMETHING_NEW", 0, {"binding_id": BINDING},
             {"action": "use_binding", "binding_id": BINDING}, state="succeeded")
    if profile == "odd":
        emit("ACCESS_READY", 0, {"binding_id": BINDING}, {"action": "observe", "operation_id": OP})
    if profile == "bad-binding":
        emit("ACCESS_READY", 0, {}, {"action": "use_binding", "binding_id": "../../not-a-binding"})
    if profile == "missing":
        refuse("NOT_FOUND", "fix_request", 2)
    if profile == "uncertain":
        refuse("OUTCOME_UNKNOWN", "reconcile", 7, effect="unknown", operation_id=OP)
    if profile in ("uncertain-unnamed", "uncertain-unlinked"):
        # `next` names no operation; the second envelope still carries its own.
        following = {"action": "reconcile"}
        own = {} if profile == "uncertain-unnamed" else {"operation_id": OP}
        emit("OUTCOME_UNKNOWN", 7, {"error": {"code": "OUTCOME_UNKNOWN", "effect_status": "unknown",
                                              "next": following}}, following, state="outcome_unknown",
             **own)
    if profile == "many":  # a binding of its own for every request
        binding = "binding_many_%d" % count("many")
        emit("ACCESS_READY", 0, {"binding_id": binding}, {"action": "use_binding", "binding_id": binding},
             state="succeeded", operation_id=OP)
    if profile == "locked":
        if count("locked") == 0 or mode == "locked-twice":
            refuse("PROVIDER_LOCKED", "interact", 3,
                   provider_interaction={"provider": "fixture_provider", "kind": "provider_unlock"})
        ready()
    if options == ["--timeout-ms", "1"]:
        emit("ACCEPTED", 5, {}, {"action": "observe", "operation_id": OP}, state="running",
             operation_id=OP)
    if options == ["--require-unattended"]:
        refuse("CAPABILITY_UNAVAILABLE", "narrow_request", 4,
               effect="partial" if mode == "effect" else "none")
    if options == ["--pair", "h3:deploy"]:
        if mode == "approval-code":
            refuse("APPROVAL_REQUIRED", "observe", 3, decision_ref=DECISION, operation_id=OP)
        refuse("INTERACTION_REQUIRED", "interact", 3, decision_ref=DECISION, operation_id=OP)
    assert not options, options
    ready()
elif args[:2] == ["operation", "wait"]:
    assert args[2:] == [OP, "--timeout-ms", "20000"], args
    if sleeps == "always":
        time.sleep(60)
    if uncertain:  # the operation of an uncertain release
        says = uncertain["says"]
        if says == "missing":
            refuse("NOT_FOUND", "fix_request", 2)
        if says == "never-ran":
            view("CAPABILITY_UNAVAILABLE", "failed", "none", {"error": {}}, exit_code=4)
        if says == "partial":
            view("OPERATION_CANCELLED", "cancelled", "partial", {"error": {}}, exit_code=4)
        if says == "unknown":
            view("OUTCOME_UNKNOWN", "outcome_unknown", "unknown", {"error": {}}, exit_code=7)
        if says == "unfinished":
            view(None, "running", "unknown", None, {"action": "observe", "operation_id": OP}, 5)
        if says == "contradictory":
            view(None, "running", "unknown", None)
        if says == "active-refusal":
            view("CAPABILITY_UNAVAILABLE", "running", "none", None, exit_code=4)
        if says == "ended-badly":
            view("OK", "failed", "none", {"error": {}})
        view("OK", "succeeded", "applied", {"outcome": "released"},
             exit_code=3 if says == "wrong-exit" else 0)
    if mode == "denied":
        view("CAPABILITY_UNAVAILABLE", "failed", "none", {"error": {}}, exit_code=4)
    if mode == "ready-while-running":  # an active view that carries a success all the same
        view("ACCESS_READY", "running", "applied", {"binding_id": BINDING})
    if mode == "still-unknown":
        view("OUTCOME_UNKNOWN", "outcome_unknown", "unknown", {"error": {}}, exit_code=7)
    # How many observations find the operation unfinished before it ends.
    unfinished = int(mode[11:]) if mode.startswith("unfinished-") else UNFINISHED.get(mode, 0)
    if unfinished and count("wait") < unfinished:
        view(None, "awaiting_approval", "none", None, {"action": "observe", "operation_id": OP}, 5)
    view("ACCESS_READY", "succeeded", "applied", {"binding_id": BINDING})
elif args[:2] == ["access", "release"]:
    assert len(args) == 3 and (args[2] in (BINDING, SECOND) or args[2].startswith("binding_many_")), args
    if sleeps in ("release", "always"):
        time.sleep(60)
    if (uncertain and args[2] in uncertain["names"].split(",")
            and count("uncertain-" + args[2]) == 0):
        following, own = {"action": "reconcile"}, {}
        if uncertain["means"] == "operation":
            following["operation_id"] = OP
        if uncertain["means"] == "own":
            own["operation_id"] = OP
        emit("OUTCOME_UNKNOWN", int(uncertain.get("exit", 7)),
             {"error": {"code": "OUTCOME_UNKNOWN", "effect_status": "unknown", "next": following}},
             following, state="outcome_unknown", **own)
    kind, _, named = mode.partition(":")
    if kind.startswith("refuse") and (named == "*" or args[2] in named.split(",")):
        if kind == "refuse-unknown":
            refuse("NOT_FOUND", "fix_request", 2)
        if kind == "refuse-novel":
            refuse("SOMETHING_NEW", "report", 1)
        if kind == "refuse-installed":
            refuse("ONLY_INSTALLED", "report", 1)
        if kind == "refuse-unavailable-exit-0":
            refuse("SERVICE_UNAVAILABLE", "retry_after", 0)
        refuse("CAPABILITY_UNAVAILABLE", "narrow_request", 0 if kind == "refuse-exit-0" else 4)
    answered = "binding_other" if mode == "other-binding" else args[2]
    emit("OK", 0, {"binding_id": answered, "outcome": {"outcome": "released"}}, state="succeeded")
elif args == ["inspect", "bindings"]:
    if sleeps == "always":
        time.sleep(60)
    says = uncertain["says"] if uncertain else "absent"
    names = uncertain["names"].split(",") if uncertain else []
    if mode.startswith("work:"):  # what the list says of the work `work-1`
        names, says = mode.split(":")[1].split(","), mode.split(":")[2]
    if says == "unknown":
        refuse("SERVICE_UNAVAILABLE", "retry_after", 5)
    states = {"active": ["active"], "released": ["released"], "odd": ["suspended"],
              "twice": ["active", "released"]}.get(says, [])
    if mode.startswith("work:") and says == "wrong-exit":
        states = ["active"]
    listed = [{"binding_id": "binding_bystander", "grant_id": "grant_fixture",
               "work_id": "work-bystander", "state": "active"}]
    for name in names:
        listed += [{"binding_id": name, "grant_id": "grant_fixture", "work_id": "work-1",
                    "state": state} for state in states]
    emit("OK", 4 if says == "wrong-exit" else 0, {"bindings": listed}, state="succeeded")
elif args[0] == "run":
    assert args[1] == "--profile" and args[3] == "--work-id" and args[5] == "--request-id", args
    assert args[7] == "--meta-file" and args[9] == "--" and Path(args[10]).is_absolute(), args
    if sleeps == "run":
        time.sleep(60)
    if args[2] == "garbled":
        print("this is no envelope", file=sys.stderr, flush=True)
        sys.exit(1)
    if mode in ("refused-launch", "refused-launch-exit-0"):
        refuse("CAPABILITY_UNAVAILABLE", "narrow_request", 4 if mode == "refused-launch" else 0,
               stream=sys.stderr)
    with open(args[8], "x", encoding="utf-8") as meta:
        print(json.dumps({"type": "launching", "schema_version": "1", "attempt": 1,
                          "executable": args[10], "operation_id": OP,
                          "binding_id": SECOND if mode == "second-binding" else BINDING,
                          "pid": 1 if mode == "other-pid" else os.getpid(),
                          "consumer_overrides": []}), file=meta)
    if sleeps == "run-recorded":
        time.sleep(60)
    if mode == "silent-child":
        sys.exit(0)
    print("up", flush=True)
    sys.stdin.read()
    if mode == "stubborn-child":
        time.sleep(60)
else:
    sys.exit(2)
'''


def plant(facts, path, value):
    keys = path.split(".")
    for key in keys[:-1]:
        facts = facts.setdefault(key, {})
    facts[keys[-1]] = value


def sample_state(name):
    return h2.State(name, **{field: SAMPLES[field] for field in h2.STATES[name]})


class TableTests(unittest.TestCase):
    def test_every_row_moves_every_state_it_names(self):
        cases = 0
        for row in h2.TRANSITIONS:
            for name in row.states:
                with self.subTest(state=name, code=row.code, action=row.action, to=row.to):
                    # An answer of the planner's own carries the code of the answer it is about.
                    facts = {"code": row.code if h2._word(row.code) else SAMPLES["code"]}
                    for field, path in row.takes:
                        if not path.startswith("="):
                            plant(facts, path, SAMPLES[field] if field != "code" else facts["code"])
                    before = sample_state(name)
                    after, chosen = h2.transition(before, h2.Reading(row.code, row.action, None, facts))
                    self.assertIs(chosen, row)
                    if row.to == h2.STAY:
                        self.assertEqual(after, before)
                    else:
                        expected = {field: path[1:] if path.startswith("=") else
                                    facts["code"] if field == "code" else SAMPLES[field]
                                    for field, path in row.takes}
                        self.assertEqual(after, h2.State(row.to, **expected))
                    cases += 1
        self.assertEqual(cases, sum(len(row.states) for row in h2.TRANSITIONS))
        self.assertGreaterEqual(cases, 50)

    def test_the_table_is_well_formed(self):
        targets = set()
        seen = set()
        for row in h2.TRANSITIONS:
            self.assertTrue(set(row.states) <= set(h2.STATES), row)
            key = (row.states, row.code, row.action, row.takes)
            self.assertNotIn(key, seen)
            seen.add(key)
            if row.to != h2.STAY:
                self.assertEqual({field for field, _ in row.takes} - set(h2.OPTIONAL.get(row.to, ())),
                                 set(h2.STATES[row.to]), row)
                targets.add(row.to)
        self.assertEqual(targets, set(h2.STATES) - {"start"})
        # Every state a goal can make a call from has a row for an exit class that does
        # not fit, unless every call it makes is about a release (RELEASE_SAYS reads
        # those). Every code a row acts on has a documented exit class.
        ended = {"stopped", "failed", "inconsistent", "unresolved"}
        self.assertEqual(set(h2.CALLING), set(h2.STATES) - ended
                         - {"running", "releasing", *h2.OBSERVING, *h2.ASKING})
        self.assertEqual(set(h2.CALLING) | set(h2.STOPPING), set(h2.STATES) - ended)
        self.assertEqual([row.states for row in h2.TRANSITIONS if row.code == h2.MISMATCH],
                         [h2.CALLING])
        # RELEASE_SAYS reads every answer to each call that is about a release: the
        # last row for a call applies to any answer. Each reading has a name for the
        # record and rows in the table, and each observing state makes an observing call.
        for call in ("release", *h2.OBSERVED_BY):
            rows = [row for row in h2.RELEASE_SAYS if row.call == call]
            self.assertEqual(tuple(rows[-1])[1:5], (None, None, None, ()), call)
            self.assertIn(call, h2.LOCAL_CALL_SET)
        self.assertEqual({row.call for row in h2.RELEASE_SAYS}, {"release", *h2.OBSERVED_BY})
        # A release is read from an operation's view only in a terminal state, and each
        # reading that takes one wants its own: the one that succeeded, or the others.
        wanted = {row.reading: dict(row.wants).get("data.state") for row in h2.RELEASE_SAYS
                  if row.call == "observe" and row.reading != h2.STILL_UNCERTAIN}
        self.assertEqual(wanted, {h2.OBSERVED: ("succeeded",), h2.NOT_RUN: ("failed", "cancelled")})
        terminal = {name for name, stage in h2.OPERATION_STATES.items() if stage.terminal}
        self.assertEqual(set(h2.SUCCEEDED) | set(h2.UNSUCCESSFUL), terminal)
        self.assertEqual(set(h2.OVER), terminal | {"outcome_unknown"})
        for name, stage in h2.OPERATION_STATES.items():
            # Only an operation that ended is observed in the class of its own code.
            self.assertEqual((stage.exit is None, stage.active and stage.terminal),
                             (stage.terminal, False), name)
            self.assertTrue(stage.terminal or not stage.succeeded, name)
        self.assertEqual({row.reading for row in h2.RELEASE_SAYS}, set(h2.OUTCOMES))
        self.assertTrue(set(h2.OUTCOMES) <= {row.code for row in h2.TRANSITIONS})
        self.assertEqual({h2.FOLLOW[name][0] for name in h2.OBSERVING}, set(h2.OBSERVED_BY))
        self.assertTrue(set(h2.SET_ASIDE) <= set(h2.OUTCOMES.values()))
        # One reading alone is followed by a new release of the same binding, and one
        # call alone can give it: the wait on the operation the uncertain answer named.
        # Nothing read from the list of bindings leads to a release.
        self.assertEqual({row.call for row in h2.RELEASE_SAYS if row.reading == h2.NOT_RUN},
                         {"observe"})
        self.assertEqual({name for row in h2.TRANSITIONS if row.code == h2.NOT_RUN
                          for name in row.states}, {"observing_release"})
        # A binding leaves the list of those held by two outcomes, and one is a release.
        # Every outcome that keeps it held, and `not_listed`, has a list in a goal's record.
        self.assertEqual(h2.NOT_HELD, ("released", "not_listed"))
        self.assertFalse(set(h2.NOT_HELD) & set(h2.SET_ASIDE))
        self.assertEqual(h2.SET_ASIDE, ("refused", "not_sent", *h2.UNKNOWN))
        # A release is remembered as uncertain after its own uncertain answer and after
        # none at all, and each fault stands for an answer of the planner's own.
        self.assertEqual({h2.OUTCOMES[reading] for reading in h2.REMEMBERED},
                         set(h2.UNKNOWN) - {"still_unknown"})
        self.assertEqual(set(h2.FAULTS.values()), {h2.NOT_STARTED, h2.UNANSWERED})
        self.assertEqual({row.code: row.reading for row in h2.RELEASE_SAYS
                          if row.call == "release" and row.code in h2.FAULTS.values()},
                         {h2.UNANSWERED: h2.SILENT, h2.NOT_STARTED: h2.UNSENT})
        # No answer never reads as a release, nor as one that never ran, whatever
        # facts come with it: for each call it is uncertain, not sent or still unknown.
        settled = {"data": {"state": "succeeded", "effect_status": "none"},
                   "binding": {"state": "released"}}
        for call in ("release", *h2.OBSERVED_BY):
            for code in h2.FAULTS.values():
                for state in ("succeeded", "failed"):
                    facts = dict(settled, data=dict(settled["data"], state=state))
                    says = h2.release_says(call, h2.Reading(code, "none", None, facts), True)
                    self.assertIn(says, (h2.SILENT, h2.UNSENT, h2.STILL_UNCERTAIN), (call, code))
        self.assertEqual(sorted(h2.RECORDED.values()), sorted(h2.SET_ASIDE + ("not_listed",)))
        # Every code a row acts on has a documented exit class, and so has every other
        # published code. An exception names a published code, and the pairing of a
        # code with an action that it names has a row.
        self.assertTrue({row.code for row in h2.TRANSITIONS if row.code.isupper()}
                        <= set(h2.EXIT_CLASSES))
        self.assertGreaterEqual(len(h2.EXIT_CLASSES), 30)
        for code, exit_class in h2.EXIT_CLASSES.items():
            self.assertTrue(h2._word(code) and code.isupper(), code)
            self.assertIn(exit_class, (*range(8), 127), code)
        for row in h2.EXIT_EXCEPTIONS:
            self.assertIn(row.code, h2.EXIT_CLASSES, row)
            self.assertNotEqual(row.exit, h2.EXIT_CLASSES[row.code], row)
            self.assertEqual(row.field is None, row.value is None, row)
            if row.action is not None:
                self.assertTrue(any((entry.code, entry.action) == (row.code, row.action)
                                    for entry in h2.TRANSITIONS), row)
        for state, (call, handoff) in h2.FOLLOW.items():
            self.assertIn(state, h2.STATES)
            self.assertTrue(call == h2.REQUEST or call in h2.LOCAL_CALL_SET)
            self.assertIn(handoff, (None, "approval", "provider"))
        for goal in h2.GOALS.values():
            self.assertIn(goal["first"], h2.LOCAL_CALL_SET)
            self.assertTrue(set(goal["accept"]) <= set(h2.STATES))

    def test_an_unknown_code_or_pairing_has_no_row(self):
        for state in h2.STATES:
            with self.subTest(state=state):
                before = sample_state(state)
                facts = {"code": "BRAND_NEW_CODE", "next": {"binding_id": "binding_sample"}}
                reading = h2.Reading("BRAND_NEW_CODE", "use_binding", None, facts)
                after, row = h2.transition(before, reading)
                self.assertIsNone(row)
                self.assertEqual(after, h2.State("failed", code="BRAND_NEW_CODE"))
                self.assertEqual(h2.no_row(before, reading), "unknown code BRAND_NEW_CODE")
        # A known code with an action no row pairs it with is no transition either.
        reading = h2.Reading("ACCESS_READY", "observe", None, {"code": "ACCESS_READY"})
        after, row = h2.transition(h2.State("start"), reading)
        self.assertIsNone(row)
        self.assertIn("no transition from start", h2.no_row(h2.State("start"), reading))

    def test_an_uncertain_outcome_is_observed_to_its_end_and_never_requested_again(self):
        named = {"code": "OUTCOME_UNKNOWN", "next": {"action": "reconcile", "operation_id": "op_sample"}}
        unnamed = {"code": "OUTCOME_UNKNOWN", "next": {"action": "reconcile"}}
        for name in h2.SENDING:
            with self.subTest(state=name):
                before = sample_state(name)
                after, row = h2.transition(before, h2.Reading("OUTCOME_UNKNOWN", "reconcile", "unknown", named))
                self.assertIsNotNone(row)
                self.assertEqual(after, h2.State("reconciling", operation_id="op_sample"))
                # An answer that names no operation is reported as it is.
                after, row = h2.transition(before, h2.Reading("OUTCOME_UNKNOWN", "reconcile", "unknown", unnamed))
                self.assertIsNotNone(row)
                self.assertEqual(after, h2.State("failed", code="OUTCOME_UNKNOWN"))
        self.assertEqual(set(h2.SENDING), {name for name, (call, _) in h2.FOLLOW.items()
                                           if call == h2.REQUEST} | {"start", "discovered", "ready"})
        # What follows `reconciling` is an observation. Every row leaves that state for
        # itself or for a state that makes no further call, so no path sends the request again.
        self.assertEqual(h2.FOLLOW["reconciling"], ("observe", None))
        leaving = [row for row in h2.TRANSITIONS if "reconciling" in row.states]
        self.assertEqual(sorted({row.to for row in leaving}),
                         sorted([h2.STAY, "ready", "failed", "inconsistent", "unresolved"]))
        for row in leaving:
            if row.to != h2.STAY:
                self.assertNotIn(row.to, h2.FOLLOW, row)
        # No row for the uncertain code leads to a state that sends the request again.
        for row in h2.TRANSITIONS:
            if row.code == "OUTCOME_UNKNOWN":
                self.assertIn(row.to, ("reconciling", "failed"), row)
        # An observation that finds the operation unfinished stays, with the same operation.
        before = h2.State("reconciling", operation_id="op_sample")
        after, row = h2.transition(before, h2.Reading("OK", "observe", "unknown", {"code": "OK"}))
        self.assertEqual((after, row.to), (before, h2.STAY))

    def test_a_failed_uncertain_outcome_names_its_operation_whenever_one_is_known(self):
        known = h2.State("failed", code="OUTCOME_UNKNOWN", operation_id="op_sample")
        # The operation's own outcome is unknown: the one being observed.
        for name in h2.IN_FLIGHT + ("reconciling",):
            with self.subTest(state=name):
                ended = h2.Reading("OUTCOME_UNKNOWN", "none", "unknown", {"code": "OUTCOME_UNKNOWN"})
                after, row = h2.transition(sample_state(name), ended)
                self.assertIsNotNone(row)
                self.assertEqual(after, known)
                self.assertEqual(after.record(), {"state": "failed", "code": "OUTCOME_UNKNOWN",
                                                  "operation_id": "op_sample"})
                # With an action no row pairs it with, there is no row, and it is still named.
                odd = ended._replace(action="report")
                self.assertEqual(h2.transition(sample_state(name), odd), (known, None))
        # The answer to a request whose `next` names none: the envelope's own, when it has one.
        own = {"code": "OUTCOME_UNKNOWN", "next": {"action": "reconcile"}, "operation_id": "op_sample"}
        after, row = h2.transition(h2.State("start"), h2.Reading("OUTCOME_UNKNOWN", "reconcile", None, own))
        self.assertIsNotNone(row)
        self.assertEqual(after, known)
        # Only this code carries one, and only when it is a well-formed operation ID.
        other = h2.Reading("POLICY_PAUSED", "report", None, dict(own, code="POLICY_PAUSED"))
        self.assertEqual(h2.transition(sample_state("observing"), other),
                         (h2.State("failed", code="POLICY_PAUSED"), None))
        with self.assertRaises(h2.PlannerError):
            h2.State("failed", code="OUTCOME_UNKNOWN", operation_id="not an operation")
        with self.assertRaises(h2.PlannerError):
            h2.State("ready", binding_id="binding_sample", operation_id="op_sample")

    def test_the_exit_class_is_checked_with_the_answer(self):
        fits = (("ACCESS_READY", "use_binding", 0), ("ACCEPTED", "observe", 5), ("OK", "observe", 5),
                ("OK", "none", 0), ("CAPABILITY_UNAVAILABLE", "narrow_request", 4),
                ("INTERACTION_REQUIRED", "interact", 3), ("OUTCOME_UNKNOWN", "reconcile", 7),
                ("launching", "none", None), ("BRAND_NEW_CODE", "none", 1))
        for code, action, status in fits:
            with self.subTest(code=code, action=action):
                reading = h2.Reading(code, action, None, {"code": code}, status)
                self.assertEqual(h2.check_exit(reading), (reading, None))
        for code, action, status in (("ACCESS_READY", "use_binding", 1), ("ACCEPTED", "observe", 0),
                                     ("OK", "observe", 0), ("OK", "none", 5),
                                     ("CAPABILITY_UNAVAILABLE", "narrow_request", 0),
                                     ("OUTCOME_UNKNOWN", "reconcile", -9)):
            with self.subTest(code=code, action=action, status=status):
                reading, problem = h2.check_exit(h2.Reading(code, action, None, {"code": code}, status))
                self.assertEqual((reading.code, reading.action, reading.exit), (h2.MISMATCH, "none", status))
                self.assertIn(f"exit {status} does not fit {code}", problem)
                after, row = h2.transition(h2.State("discovered"), reading)
                self.assertIsNotNone(row)
                self.assertEqual(after.record(), {"state": "inconsistent", "code": code,
                                                  "exit_code": status})
        self.assertNotIn("inconsistent", h2.FOLLOW)
        self.assertFalse(any("inconsistent" in goal["accept"] for goal in h2.GOALS.values()))

    def test_every_published_code_has_its_exit_class_checked(self):
        # M07-W5-R03: not only the codes the transition table acts on.
        for code, documented in h2.EXIT_CLASSES.items():
            excepted = [row for row in h2.EXIT_EXCEPTIONS
                        if row.code == code and (row.action, row.field) == (None, None)]
            documented = excepted[0].exit if excepted else documented
            with self.subTest(code=code):
                fits = h2.Reading(code, "report", None, {"code": code}, documented)
                self.assertEqual(h2.check_exit(fits), (fits, None))
                reading, problem = h2.check_exit(fits._replace(exit=documented + 1))
                self.assertEqual(reading.code, h2.MISMATCH)
                self.assertEqual(problem, f"exit {documented + 1} does not fit {code}: "
                                          f"its documented exit class is {documented}")
        # The command-specific exceptions: the bounded wait, the observation that found
        # its operation unfinished, and the launch of a program that cannot be run.
        launch = lambda reason: {"code": "LAUNCH_FAILED", "data": {"error": {"reason": reason}}}
        for code, action, facts, documented in (
                ("ACCEPTED", "observe", {}, 5), ("OK", "observe", {}, 5), ("OK", "none", {}, 0),
                ("LAUNCH_FAILED", "report", launch("not_executable"), 126),
                ("LAUNCH_FAILED", "report", launch("exec_error"), 127),
                ("LAUNCH_FAILED", "report", {}, 127)):
            with self.subTest(code=code, action=action, facts=facts):
                reading = h2.Reading(code, action, None, facts, documented)
                self.assertEqual(h2.documented_exit(reading), (documented, code))
                self.assertEqual(h2.check_exit(reading), (reading, None))
                self.assertIsNotNone(h2.check_exit(reading._replace(exit=0 if documented else 1))[1])
        # The installed table's class is the one checked where discovery read one, for a
        # code the frozen table has and for one it lacks. A row that gives no usable
        # class leaves the frozen one, and an exception stands whatever the table says.
        installed = {"SERVICE_UNAVAILABLE": 6, "ONLY_INSTALLED": 6, "NOT_FOUND": None,
                     "OK": True, "POLICY_PAUSED": "4", "ACCEPTED": 0}
        for code, action, documented in (("SERVICE_UNAVAILABLE", "retry_after", 6),
                                         ("ONLY_INSTALLED", "report", 6), ("NOT_FOUND", "fix_request", 2),
                                         ("OK", "none", 0), ("POLICY_PAUSED", "owner_decision", 4),
                                         ("ACCEPTED", "observe", 5), ("BRAND_NEW_CODE", "none", None)):
            with self.subTest(installed=code):
                reading = h2.Reading(code, action, None, {"code": code}, 99)
                self.assertEqual(h2.documented_exit(reading, installed), (documented, code))
                self.assertEqual(h2.check_exit(reading, installed)[1] is None, documented is None)
        self.assertEqual(h2.documented_exit(h2.Reading("ONLY_INSTALLED", "report", None, {}, 1)),
                         (None, "ONLY_INSTALLED"))

    def test_the_frozen_tables_are_the_published_ones(self):
        published = SOURCE.parents[3] / "schemas" / "public-api"
        if not published.is_dir():
            self.skipTest("the published schemas are not beside this example")
        table = json.loads((published / "codes.json").read_text(encoding="utf-8"))
        self.assertEqual(h2.EXIT_CLASSES, {row["code"]: row["exit_code"] for row in table["codes"]})
        # The operation states, and which of them are terminal: the schema calls those
        # settled, and no other.
        schema = json.loads((published / "envelope.schema.json").read_text(encoding="utf-8"))
        states = {entry["const"]: entry["description"]
                  for entry in schema["$defs"]["OperationState"]["oneOf"]}
        self.assertEqual(set(h2.OPERATION_STATES), set(states))
        self.assertEqual({name for name, stage in h2.OPERATION_STATES.items() if stage.terminal},
                         {name for name, description in states.items()
                          if description.startswith("Settled:")})
        self.assertEqual(h2.SUCCEEDED, ("succeeded",))

    def test_an_operation_view_is_read_by_its_typed_state(self):
        # M07-W5-R02. (the view's state, its own code; the answer's code as read, the
        # state the facts gain, the exit class documented for the observation)
        def answer(state, code, action="none"):
            view = {"operation_id": "op_sample", "state": state, "code": code,
                    "effect_status": "none", "result": None}
            return {"schema_version": "1", "code": "OK", "data": view,
                    "next": None if action == "none" else {"action": action}}
        rows = (
            # still going: its own code is not the answer's, whatever it is
            ("queued", None, "OK", "queued", 5),
            ("running", None, "OK", "running", 5),
            ("running", "OK", "OK", "running", 5),
            ("running", "ACCESS_READY", "OK", "running", 5),
            ("running", "CAPABILITY_UNAVAILABLE", "OK", "running", 5),
            ("awaiting_approval", "APPROVAL_REQUIRED", "OK", "awaiting_approval", 5),
            # ended: the class of its own code
            ("succeeded", "ACCESS_READY", "ACCESS_READY", "succeeded", 0),
            ("succeeded", "OK", "OK", "succeeded", 0),
            ("succeeded", None, "OK", "succeeded", 0),
            ("failed", "CAPABILITY_UNAVAILABLE", "CAPABILITY_UNAVAILABLE", "failed", 4),
            ("cancelled", "OPERATION_CANCELLED", "OPERATION_CANCELLED", "cancelled", 4),
            ("failed", None, "OK", "failed", None),  # ended badly and names no code
            # unresolved: its own code, in the class of an uncertain outcome
            ("outcome_unknown", "OUTCOME_UNKNOWN", "OUTCOME_UNKNOWN", "outcome_unknown", 7),
            ("outcome_unknown", None, "OK", "outcome_unknown", 7),
            # in no state the table has: read as unfinished, with no state to check by
            ("finished", "ACCESS_READY", "OK", None, 0),
            (None, "ACCESS_READY", "OK", None, 0),
            (["succeeded"], "ACCESS_READY", "OK", None, 0),
        )
        for state, own, code, observed, documented in rows:
            with self.subTest(state=state, code=own):
                reading = h2.read_operation(answer(state, own), "op_sample")
                self.assertEqual((reading.code, reading.facts["code"]), (code, code))
                self.assertEqual(h2.lookup(reading.facts, "observed.state"), observed)
                self.assertEqual(h2.documented_exit(reading)[0], documented)
        # The mismatch names the state where the class is the state's own.
        active = h2.read_operation(answer("running", None), "op_sample")._replace(exit=0)
        self.assertEqual(h2.check_exit(active)[1], "exit 0 does not fit an operation that is "
                                                   "running: its documented exit class is 5")
        self.assertEqual(h2.check_exit(active._replace(exit=5)), (active._replace(exit=5), None))
        # An answer that is no view of an operation gains nothing.
        refused = {"schema_version": "1", "code": "NOT_FOUND", "data": {"state": "running"},
                   "next": {"action": "fix_request"}}
        self.assertIsNone(h2.lookup(h2.read_operation(refused, "op_sample").facts, "observed.state"))
        with self.assertRaises(h2.PlannerError):
            h2.read_operation(answer("succeeded", "ACCESS_READY"), "op_other")
        with self.assertRaises(h2.PlannerError):
            h2.read_operation(answer("succeeded", "not a code"), "op_sample")

    def test_the_step_limit_while_reconciling_reports_the_operation(self):
        before = h2.State("reconciling", operation_id="op_sample")
        limit = h2.Reading(h2.BOUND, "none", None, {"state": dict(before.fields)})
        after, row = h2.transition(before, limit)
        self.assertIsNotNone(row)
        self.assertEqual(after, h2.State("unresolved", code="OUTCOME_UNKNOWN", operation_id="op_sample"))
        self.assertEqual(after.record(), {"state": "unresolved", "code": "OUTCOME_UNKNOWN",
                                          "operation_id": "op_sample"})
        # Only `reconciling` has a row for the step limit, and that state ends the goal.
        self.assertEqual([row.states for row in h2.TRANSITIONS if row.code == h2.BOUND],
                         [("reconciling",)])
        self.assertNotIn("unresolved", h2.FOLLOW)
        self.assertFalse(any("unresolved" in row.states for row in h2.TRANSITIONS))
        self.assertFalse(any("unresolved" in goal["accept"] for goal in h2.GOALS.values()))
        # No answer can stand in for the step limit: an envelope's code is a word.
        with self.assertRaises(h2.PlannerError):
            h2.read_envelope({"schema_version": "1", "code": h2.BOUND})

    def test_a_release_goes_on_to_the_next_held_binding(self):
        for name in h2.HELD + ("releasing",):
            with self.subTest(state=name):
                before = sample_state(name)
                more = {"code": "OK", "held": {"binding_id": "binding_older"}}
                after, row = h2.transition(before, h2.Reading("OK", "none", None, more))
                self.assertEqual(after, h2.State("releasing", binding_id="binding_older"))
                after, row = h2.transition(before, h2.Reading("OK", "none", None, {"code": "OK", "held": {}}))
                self.assertEqual(after, h2.State("stopped"))
        self.assertEqual(h2.FOLLOW["releasing"], ("release", None))

    def test_a_refused_release_goes_on_to_the_next_binding_and_fails_the_stop(self):
        refused = {"binding_id": "binding_refused", "code": "CAPABILITY_UNAVAILABLE", "exit_code": 4}
        failed = h2.State("failed", **refused)
        self.assertEqual(failed.record(), dict(refused, state="failed"))
        for name in h2.RELEASABLE:
            with self.subTest(state=name):
                before = sample_state(name)
                more = {"held": {"binding_id": "binding_older"}, "unreleased": refused}
                last = {"held": {}, "unreleased": refused}
                # The refusal itself: on to the next binding, or the end of the stop.
                after, row = h2.transition(before, h2.Reading(h2.REFUSED, "none", None, more))
                self.assertEqual((after, row.to), (h2.State("releasing", binding_id="binding_older"),
                                                   "releasing"))
                after, row = h2.transition(before, h2.Reading(h2.REFUSED, "none", None, last))
                self.assertEqual((after, row.to), (failed, "failed"))
                # A later release that is answered: the stop still fails once none is left.
                after, row = h2.transition(before, h2.Reading("OK", "none", None, dict(more, code="OK")))
                self.assertEqual(after, h2.State("releasing", binding_id="binding_older"))
                after, row = h2.transition(before, h2.Reading("OK", "none", None, dict(last, code="OK")))
                self.assertEqual((after, row.to), (failed, "failed"))
        # Only a release leads there, and no envelope can stand in for the planner's reading.
        self.assertEqual({row.states for row in h2.TRANSITIONS if row.code == h2.REFUSED},
                         {h2.RELEASABLE})
        self.assertNotIn("failed", h2.FOLLOW)
        self.assertNotIn("failed", h2.GOALS["stop"]["accept"])
        with self.assertRaises(h2.PlannerError):
            h2.read_envelope({"schema_version": "1", "code": h2.REFUSED})

    def test_what_an_answer_says_about_a_release(self):
        view = lambda effect, state: {"data": {"effect_status": effect, "state": state}}
        stateless = lambda effect: {"data": {"effect_status": effect}}
        listed = lambda state: {"binding": {"state": state}}
        refused, uncertain, observed, not_run = h2.REFUSED, h2.UNCERTAIN, h2.OBSERVED, h2.NOT_RUN
        # An observation never reads as the release's own uncertain answer, and the
        # other way about: one that settles nothing is `still`.
        still, not_listed = h2.STILL_UNCERTAIN, h2.NOT_LISTED
        # (the call, the code, next.action, whether the exit class fits, typed facts, the reading)
        rows = (
            # the release itself
            ("release", "OK", "none", True, {}, "OK"),
            ("release", "OK", "none", False, {}, refused),
            ("release", "OK", "observe", True, {}, refused),
            ("release", "CAPABILITY_UNAVAILABLE", "narrow_request", True, {}, refused),
            ("release", "CAPABILITY_UNAVAILABLE", "narrow_request", False, {}, refused),
            ("release", "NOT_FOUND", "fix_request", True, {}, refused),
            ("release", "BRAND_NEW_CODE", "report", True, {}, refused),
            # uncertain whatever its exit status and whatever follows: never a refusal
            ("release", "OUTCOME_UNKNOWN", "reconcile", True, {}, uncertain),
            ("release", "OUTCOME_UNKNOWN", "reconcile", False, {}, uncertain),
            ("release", "OUTCOME_UNKNOWN", "none", True, {}, uncertain),
            # M07-W5-R01: no answer. A release that was started may have happened; one
            # that was never started was not sent. An observation settles nothing
            ("release", h2.UNANSWERED, "none", True, {}, h2.SILENT),
            ("release", h2.NOT_STARTED, "none", True, {}, h2.UNSENT),
            ("observe", h2.UNANSWERED, "none", True, view("none", "failed"), still),
            ("observe", h2.NOT_STARTED, "none", True, {}, still),
            ("bindings", h2.UNANSWERED, "none", True, listed("released"), still),
            ("bindings", h2.NOT_STARTED, "none", True, listed(h2.ABSENT), still),
            # its operation, waited on
            ("observe", "OK", "none", True, view("applied", "succeeded"), observed),
            ("observe", "OK", "none", False, view("applied", "succeeded"), still),
            ("observe", "OK", "observe", True, view("none", "awaiting_approval"), still),  # unfinished
            ("observe", "OK", "observe", True, view("unknown", "running"), still),  # unfinished
            ("observe", "OUTCOME_UNKNOWN", "none", True, view("unknown", "outcome_unknown"), still),
            ("observe", "OUTCOME_UNKNOWN", "none", True, view("none", "outcome_unknown"), still),
            # M07-W5-R02: only a terminal view of an operation that succeeded is
            # evidence of a release, whatever its envelope and its exit status say
            ("observe", "OK", "none", True, view("unknown", "running"), still),
            ("observe", "OK", "none", True, view("applied", "queued"), still),
            ("observe", "OK", "none", True, view("applied", "awaiting_approval"), still),
            ("observe", "OK", "none", True, view("applied", "outcome_unknown"), still),
            ("observe", "OK", "none", True, view("applied", "failed"), still),
            ("observe", "OK", "none", True, view("applied", "cancelled"), still),
            ("observe", "OK", "none", True, view("applied", "finished"), still),  # no such state
            ("observe", "OK", "none", True, view("applied", ["succeeded"]), still),
            ("observe", "OK", "none", True, stateless("applied"), still),
            # it ended without succeeding, and its result says the release did not happen
            ("observe", "CAPABILITY_UNAVAILABLE", "none", True, view("none", "failed"), not_run),
            ("observe", "OPERATION_CANCELLED", "none", True, view("none", "cancelled"), not_run),
            ("observe", "OPERATION_CANCELLED", "none", True, view("partial", "cancelled"), still),
            ("observe", "OPERATION_CANCELLED", "none", True, view("applied", "cancelled"), still),
            ("observe", "OPERATION_CANCELLED", "none", True, view("unknown", "cancelled"), still),
            ("observe", "OPERATION_CANCELLED", "none", True, {"data": {"state": "cancelled"}}, still),
            ("observe", "OPERATION_CANCELLED", "none", False, view("none", "cancelled"), still),
            ("observe", "OPERATION_CANCELLED", "report", True, view("none", "cancelled"), still),
            # and only a terminal view says so: never one of an operation still going,
            # unresolved, succeeded, or in no state the table has
            ("observe", "CAPABILITY_UNAVAILABLE", "none", True, view("none", "running"), still),
            ("observe", "CAPABILITY_UNAVAILABLE", "none", True, view("none", "queued"), still),
            ("observe", "CAPABILITY_UNAVAILABLE", "none", True, view("none", "outcome_unknown"), still),
            ("observe", "CAPABILITY_UNAVAILABLE", "none", True, view("none", "succeeded"), still),
            ("observe", "CAPABILITY_UNAVAILABLE", "none", True, view("none", "finished"), still),
            ("observe", "CAPABILITY_UNAVAILABLE", "none", True, stateless("none"), still),
            # the observation itself was refused: its effect is not the operation's
            ("observe", "NOT_FOUND", "fix_request", True,
             {"data": {"error": {"effect_status": "none"}}}, still),
            # its binding's own state, in the complete list. `active` alone is not
            # evidence that the release never ran; a binding the list does not name is
            # not listed, and is not read as released
            ("bindings", "OK", "none", True, listed("active"), still),
            ("bindings", "OK", "none", True, listed("released"), observed),
            ("bindings", "OK", "none", True, listed(h2.ABSENT), not_listed),
            ("bindings", "OK", "none", True, listed("suspended"), still),
            ("bindings", "OK", "none", True, {}, still),  # the list says nothing of it
            ("bindings", "OK", "none", False, listed("active"), still),
            ("bindings", "OK", "none", False, listed("released"), still),
            ("bindings", "OK", "none", False, listed(h2.ABSENT), still),
            ("bindings", "OK", "observe", True, listed("active"), still),
            ("bindings", "OK", "observe", True, listed(h2.ABSENT), still),
            ("bindings", "SERVICE_UNAVAILABLE", "retry_after", True, {}, still),
        )
        for call, code, action, fits, facts, reading in rows:
            with self.subTest(call=call, code=code, action=action, fits=fits, facts=facts):
                answer = h2.Reading(code, action, None, dict(facts, code=code))
                self.assertEqual(h2.release_says(call, answer, fits), reading)
                # Nothing the list of bindings says is followed by a new release.
                if call == "bindings":
                    self.assertNotEqual(h2.release_says(call, answer, fits), not_run)

    def test_the_list_of_bindings_is_reduced_to_the_state_of_one(self):
        entry = lambda binding, state: {"binding_id": binding, "grant_id": "grant_sample",
                                        "state": state}
        ok = lambda data: {"schema_version": "1", "code": "OK", "data": data, "next": None}
        mine, other = "binding_sample", "binding_other"
        # (the envelope, what it says of `binding_sample`: None when it says nothing)
        rows = (
            (ok({"bindings": [entry(mine, "active")]}), "active"),
            (ok({"bindings": [entry(other, "active"), entry(mine, "released")]}), "released"),
            (ok({"bindings": [entry(other, "active")]}), h2.ABSENT),
            (ok({"bindings": []}), h2.ABSENT),
            (ok({"bindings": [entry(mine, "active"), entry(mine, "released")]}), None),
            (ok({"bindings": [entry(mine, ["active"])]}), None),
            (ok({"bindings": [entry(mine, "active"), other]}), None),  # not a list of entries
            (ok({"items": [], "more": False}), None),  # a page is not the complete list
            (ok(None), None),
            ({"schema_version": "1", "code": "SERVICE_UNAVAILABLE", "data": {"bindings": []},
              "next": {"action": "retry_after"}}, None),
        )
        for envelope, state in rows:
            with self.subTest(envelope=envelope):
                reading = h2.read_bindings(envelope, mine)
                self.assertEqual(h2.lookup(reading.facts, "binding.state"), state)
                self.assertEqual(reading.code, envelope["code"])

    def test_an_uncertain_release_is_observed_and_only_its_ended_operation_leads_to_a_new_release(self):
        unknown = {"binding_id": "binding_unknown", "code": "OUTCOME_UNKNOWN", "exit_code": 7}
        named = dict(unknown, operation_id="op_unknown")
        older = lambda **more: dict({"binding_id": "binding_older"}, **more)
        # (the planner's own facts, the state a stop goes on to)
        onward = (
            ({"held": older()}, h2.State("releasing", binding_id="binding_older")),
            ({"uncertain": older(operation_id="op_older")},
             h2.State("observing_release", binding_id="binding_older", operation_id="op_older")),
            ({"uncertain": older()}, h2.State("inspecting_release", binding_id="binding_older")),
        )
        # A release left uncertain by its own answer, and an observation that does not
        # say what became of it: on to the next binding by what the planner knows of
        # it, and `failed` at the end. Each is read only in the states that make its call.
        for own, states in ((h2.UNCERTAIN, h2.RELEASABLE), (h2.SILENT, h2.RELEASABLE),
                            (h2.UNSENT, h2.RELEASABLE), (h2.STILL_UNCERTAIN, h2.OBSERVING)):
            for name in states:
                before = sample_state(name)
                for facts, after in onward + (({}, h2.State("failed", **unknown)),):
                    with self.subTest(reading=own, state=name, facts=facts):
                        reading = h2.Reading(own, "none", None, dict(facts, unreleased=unknown))
                        self.assertEqual(h2.transition(before, reading)[0], after)
                reading = h2.Reading(own, "none", None, {"unreleased": named})
                self.assertEqual(h2.transition(before, reading)[0].record(),
                                 dict(named, state="failed"))
                # The call about that binding had no exit status: it ran past its time
                # limit, or it was never started (its fault stands where the code would).
                for code, operation in (("OUTCOME_UNKNOWN", {"operation_id": "op_unknown"}),
                                        ("OUTCOME_UNKNOWN", {}), ("not_started", {})):
                    late = dict({"binding_id": "binding_unknown", "code": code}, **operation)
                    reading = h2.Reading(own, "none", None, {"unreleased": dict(late, exit_code=None)})
                    self.assertEqual(h2.transition(before, reading)[0].record(),
                                     dict(late, state="failed"))
            self.assertEqual({row.states for row in h2.TRANSITIONS if row.code == own}, {states})
        # No longer held: observed to have been released, by either observation; or not
        # listed, which only the list of bindings can say. On in the same ways, or the
        # end of the stop.
        for own, states in ((h2.OBSERVED, h2.OBSERVING), (h2.NOT_LISTED, h2.INSPECTING)):
            for name in states:
                before = sample_state(name)
                for facts, after in onward + (({}, h2.State("stopped")),
                                              ({"unreleased": unknown}, h2.State("failed", **unknown))):
                    with self.subTest(reading=own, state=name, facts=facts):
                        reading = h2.Reading(own, "none", None, facts)
                        self.assertEqual(h2.transition(before, reading)[0], after)
            self.assertEqual({row.states for row in h2.TRANSITIONS if row.code == own}, {states})
        # The operation ended and says that the release did not happen: one new
        # release, of the same binding, whatever else is held.
        reading = h2.Reading(h2.NOT_RUN, "none", None, {"held": older()})
        after, row = h2.transition(sample_state("observing_release"), reading)
        self.assertEqual((after, row.to),
                         (h2.State("releasing", binding_id=SAMPLES["binding_id"]), "releasing"))
        # What follows an observing state is an observation. One row alone leads from
        # there to a release of the same binding. It is a row of the state that waits
        # on an operation, never of the one that reads the list of bindings, and it is
        # not a row for an uncertain reading. Every other row that leads to a release
        # names another binding.
        self.assertEqual((h2.WAITING, h2.INSPECTING, h2.OBSERVING),
                         (("observing_release",), ("inspecting_release",),
                          ("observing_release", "inspecting_release")))
        self.assertEqual([h2.FOLLOW[name] for name in h2.OBSERVING],
                         [("observe", None), ("bindings", None)])
        self.assertEqual([(row.states, row.to, row.takes) for row in h2.TRANSITIONS
                          if row.code == h2.NOT_RUN],
                         [(("observing_release",), "releasing", (("binding_id", "state.binding_id"),))])
        for row in h2.TRANSITIONS:
            if row.to == "releasing" and row.code != h2.NOT_RUN:
                self.assertEqual(row.takes, h2.NEXT_HELD, row)
            if row.code in (h2.UNCERTAIN, h2.SILENT, h2.UNSENT, h2.STILL_UNCERTAIN):
                self.assertIn(row.to, ("releasing", *h2.OBSERVING, "failed"), row)
            if "inspecting_release" in row.states:  # the list of bindings never ends in a release
                self.assertIn(row.code, (h2.OBSERVED, h2.NOT_LISTED, h2.STILL_UNCERTAIN), row)
        # A stop begins at a binding in the same ways.
        for facts, after in onward:
            self.assertEqual(h2.entering(facts), after)
        # No envelope can stand in for one of the planner's own readings.
        for own in (h2.UNCERTAIN, h2.STILL_UNCERTAIN, h2.OBSERVED, h2.NOT_RUN, h2.NOT_LISTED,
                    h2.ABSENT, h2.SILENT, h2.UNSENT, h2.UNANSWERED, h2.NOT_STARTED):
            with self.assertRaises(h2.PlannerError):
                h2.read_envelope({"schema_version": "1", "code": own})

    def test_a_call_with_no_answer_keeps_what_its_first_complete_line_said(self):
        # M07-W5-R01. What a call printed before it ran past its time limit, or beside
        # an answer that cannot be read, is kept from typed fields only.
        def line(code, operation=None, following=None):
            return json.dumps({"schema_version": "1", "code": code, "data": None,
                               "operation_id": operation, "next": following}).encode() + b"\n"
        named = line("OUTCOME_UNKNOWN", None, {"action": "reconcile", "operation_id": "op_sample"})
        late = "a CLI call ran past its time limit"
        # A complete `OUTCOME_UNKNOWN` line is kept whole, with its operation: it is
        # the uncertain answer it says it is. The process has no exit status.
        kept = h2.no_answer("timed_out", late, named).reading
        self.assertEqual((kept.code, kept.action, kept.exit), ("OUTCOME_UNKNOWN", "reconcile", None))
        self.assertEqual(h2.lookup(kept.facts, "next.operation_id"), "op_sample")
        self.assertEqual((kept.facts["fault"], kept.facts["problem"]), ("timed_out", late))
        self.assertEqual(h2.release_says("release", kept, True), h2.UNCERTAIN)
        # Followed by more output, it is still that; and the exit status is kept.
        kept = h2.no_answer("unreadable", "two lines", named + b"more\n", 7).reading
        self.assertEqual((kept.code, kept.exit, kept.facts["fault"]), ("OUTCOME_UNKNOWN", 7, "unreadable"))
        # (the output; the code and the operations kept from it)
        rows = (
            (None, None, None, None),
            (b"", None, None, None),
            (named[:-1], None, None, None),  # the line is not complete
            (b"not JSON\n", None, None, None),
            (b'{"schema_version": "2", "code": "OK"}\n', None, None, None),
            # No other answer is taken from it: not `OK`, and not a refusal. Its code
            # and the operations it names are kept for the record and the observation.
            (line("OK", "op_own"), "OK", "op_own", None),
            (line("OK") + b"{", "OK", None, None),
            (line("CAPABILITY_UNAVAILABLE", "op_own", {"action": "observe", "operation_id": "op_next"}),
             "CAPABILITY_UNAVAILABLE", "op_own", "op_next"),
        )
        for output, code, own, following in rows:
            with self.subTest(output=output):
                silent = h2.no_answer("timed_out", late, output)
                self.assertEqual(str(silent), late)
                reading = silent.reading
                self.assertEqual((reading.code, reading.action, reading.exit), (h2.UNANSWERED, "none", None))
                self.assertEqual((reading.facts["code"], reading.facts.get("operation_id"),
                                  h2.lookup(reading.facts, "next.operation_id")), (code, own, following))
                self.assertEqual(h2.check_exit(reading), (reading, None))
                self.assertEqual(h2.release_says("release", reading, True), h2.SILENT)
        # A call that was never started printed nothing, and was not sent.
        reading = h2.no_answer("not_started", "the CLI could not be started").reading
        self.assertEqual((reading.code, reading.facts), (h2.NOT_STARTED, {
            "code": None, "fault": "not_started", "problem": "the CLI could not be started"}))
        self.assertEqual(h2.release_says("release", reading, True), h2.UNSENT)

    def test_what_an_observation_says_about_a_request(self):
        # M07 W6b: a request (`access ensure`, `run`) that brought no answer, observed.
        view = lambda effect, state, binding="binding_made": {"data": {
            "effect_status": effect, "state": state, "result": {"binding_id": binding}}}
        work = lambda found: {"work": {"active": [], "found": found}}
        found, never, still = h2.FOUND, h2.NEVER_RAN, h2.STILL_OPEN
        # (the call, the code, next.action, whether the exit class fits, typed facts, the reading)
        rows = (
            # its operation: only a terminal view of one that succeeded, and that names
            # the binding it made, is evidence of a binding
            ("observe", "ACCESS_READY", "none", True, view("applied", "succeeded"), found),
            ("observe", "ACCESS_READY", "none", False, view("applied", "succeeded"), still),
            ("observe", "ACCESS_READY", "observe", True, view("applied", "succeeded"), still),
            ("observe", "ACCESS_READY", "none", True, view("applied", "succeeded", "../no-binding"), still),
            ("observe", "ACCESS_READY", "none", True, view("applied", "succeeded", None), still),
            ("observe", "ACCESS_READY", "none", True, view("applied", "succeeded", ["binding_made"]), still),
            ("observe", "ACCESS_READY", "none", True, view("applied", "running"), still),
            ("observe", "ACCESS_READY", "none", True, view("applied", "outcome_unknown"), still),
            ("observe", "ACCESS_READY", "none", True, view("applied", "finished"), still),  # no such state
            # a success that says nothing of access, and an operation that is unfinished
            ("observe", "OK", "none", True, view("applied", "succeeded"), still),
            ("observe", "OK", "observe", True, view("none", "awaiting_approval"), still),
            ("observe", "OK", "none", True, view("unknown", "running"), still),
            ("observe", "OUTCOME_UNKNOWN", "none", True, view("unknown", "outcome_unknown"), still),
            # it ended without succeeding and reports no effect: the request did not
            # happen. Only a terminal view says so, and never one that names a success
            ("observe", "CAPABILITY_UNAVAILABLE", "none", True, view("none", "failed"), never),
            ("observe", "OPERATION_CANCELLED", "none", True, view("none", "cancelled"), never),
            ("observe", "OPERATION_CANCELLED", "none", True, view("partial", "cancelled"), still),
            ("observe", "OPERATION_CANCELLED", "none", True, view("applied", "cancelled"), still),
            ("observe", "OPERATION_CANCELLED", "none", True, view("unknown", "cancelled"), still),
            ("observe", "OPERATION_CANCELLED", "none", False, view("none", "cancelled"), still),
            ("observe", "OPERATION_CANCELLED", "report", True, view("none", "cancelled"), still),
            ("observe", "CAPABILITY_UNAVAILABLE", "none", True, view("none", "running"), still),
            ("observe", "CAPABILITY_UNAVAILABLE", "none", True, view("none", "outcome_unknown"), still),
            ("observe", "CAPABILITY_UNAVAILABLE", "none", True, view("none", "succeeded"), still),
            ("observe", "ACCESS_READY", "none", True, view("none", "failed"), still),
            ("observe", "OK", "none", True, view("none", "failed"), still),
            # the observation itself was refused, or brought no answer
            ("observe", "NOT_FOUND", "fix_request", True,
             {"data": {"error": {"effect_status": "none"}}}, still),
            ("observe", h2.UNANSWERED, "none", True, view("applied", "succeeded"), still),
            ("observe", h2.NOT_STARTED, "none", True, view("none", "failed"), still),
            ("work", h2.UNANSWERED, "none", True, work(h2.NEW), still),
            ("work", h2.NOT_STARTED, "none", True, work(h2.NEW), still),
            # the complete list of bindings, read for its work: a binding it names for
            # that work, `active` and not held, is one to release. A list that names
            # none is no evidence that the request never ran
            ("work", "OK", "none", True, work(h2.NEW), found),
            ("work", "OK", "none", True, work(h2.NONE_NEW), still),
            ("work", "OK", "none", True, {}, still),  # the list says nothing of the work
            ("work", "OK", "none", False, work(h2.NEW), still),
            ("work", "OK", "observe", True, work(h2.NEW), still),
            ("work", "SERVICE_UNAVAILABLE", "retry_after", True, work(h2.NEW), still),
        )
        for call, code, action, fits, facts, reading in rows:
            with self.subTest(call=call, code=code, action=action, fits=fits, facts=facts):
                answer = h2.Reading(code, action, None, dict(facts, code=code))
                self.assertEqual(h2.request_says(call, answer, fits), reading)
                # Nothing the list of bindings says reads as a request that never ran.
                if call == "work":
                    self.assertNotEqual(h2.request_says(call, answer, fits), never)
        # The table reads every answer to each observing call: the last row for a call
        # applies to any answer. Each reading has a name for the record and rows in the
        # transition table, and each observing state makes an observing call.
        for call in h2.REQUEST_OBSERVED_BY:
            rows = [row for row in h2.REQUEST_SAYS if row.call == call]
            self.assertEqual(tuple(rows[-1])[1:5], (None, None, None, ()), call)
            self.assertIn(call, h2.LOCAL_CALL_SET)
        self.assertEqual({row.call for row in h2.REQUEST_SAYS}, set(h2.REQUEST_OBSERVED_BY))
        self.assertEqual({row.reading for row in h2.REQUEST_SAYS} | set(h2.FAULTS.values()),
                         set(h2.REQUEST_OUTCOMES))
        self.assertTrue(set(h2.REQUEST_OUTCOMES) <= {row.code for row in h2.TRANSITIONS})
        self.assertEqual({h2.FOLLOW[name][0] for name in h2.ASKING}, set(h2.REQUEST_OBSERVED_BY))
        self.assertEqual({row.call for row in h2.REQUEST_SAYS if row.reading == never}, {"observe"})
        wanted = {row.reading: dict(row.wants).get("data.state") for row in h2.REQUEST_SAYS
                  if row.call == "observe" and row.reading != still}
        self.assertEqual(wanted, {found: ("succeeded",), never: ("failed", "cancelled")})
        self.assertEqual(h2.SETTLED, (found, never))
        self.assertEqual(sorted(h2.REQUEST_RECORDED.values()),
                         sorted(set(h2.REQUEST_OUTCOMES.values()) - {"binding_found", "not_run"}))
        # No envelope can stand in for one of the planner's own readings.
        for own in (found, never, still):
            with self.assertRaises(h2.PlannerError):
                h2.read_envelope({"schema_version": "1", "code": own})

    def test_the_list_of_bindings_is_reduced_to_the_active_bindings_of_one_work(self):
        entry = lambda binding, work, state: {"binding_id": binding, "grant_id": "grant_sample",
                                              "work_id": work, "state": state}
        ok = lambda data: {"schema_version": "1", "code": "OK", "data": data, "next": None}
        mine, other = "work-sample", "work-other"
        # (the envelope, the bindings it names for `work-sample` in the state `active`:
        #  None when it says nothing of the work)
        rows = (
            (ok({"bindings": [entry("binding_a", mine, "active"), entry("binding_b", other, "active"),
                              entry("binding_c", mine, "released"), entry("binding_d", mine, "active")]}),
             ["binding_a", "binding_d"]),
            (ok({"bindings": [entry("binding_a", mine, "active")] * 2}), ["binding_a"]),
            (ok({"bindings": [entry("binding_b", other, "active")]}), []),
            (ok({"bindings": []}), []),
            (ok({"bindings": [entry("binding_a", mine, "suspended")]}), []),
            (ok({"bindings": [entry("binding_a", mine, ["active"])]}), []),
            # an entry that names no work is not of this one
            (ok({"bindings": [{"binding_id": "binding_a", "state": "active"}]}), []),
            (ok({"bindings": [entry("../no-binding", mine, "active")]}), None),
            (ok({"bindings": [entry("binding_a", mine, "active"), "binding_b"]}), None),
            (ok({"items": [], "more": False}), None),  # a page is not the complete list
            (ok(None), None),
            ({"schema_version": "1", "code": "SERVICE_UNAVAILABLE",
              "data": {"bindings": [entry("binding_a", mine, "active")]},
              "next": {"action": "retry_after"}}, None),
        )
        for envelope, active in rows:
            with self.subTest(envelope=envelope):
                reading = h2.read_work(envelope, mine)
                self.assertEqual(h2.lookup(reading.facts, "work.active"), active)
                self.assertEqual(reading.code, envelope["code"])

    def test_a_request_with_no_answer_ends_its_goal_and_a_stop_observes_it_first(self):
        mine = {"request_id": "request-late"}
        unsettled = dict(mine, code="OUTCOME_UNKNOWN")
        # The request itself, read by its fault. One that was started is uncertain, and
        # `failed` names it with the operation it named. One that was never started has
        # its fault where the code would be. Neither state sends anything.
        for name in h2.SENDING:
            with self.subTest(state=name):
                before = sample_state(name)
                named = h2.Reading(h2.UNANSWERED, "none", None,
                                   {"request": dict(mine, operation_id="op_named")})
                self.assertEqual(h2.transition(before, named)[0].record(),
                                 dict(unsettled, state="failed", operation_id="op_named"))
                unnamed = h2.Reading(h2.UNANSWERED, "none", None, {"request": mine})
                self.assertEqual(h2.transition(before, unnamed)[0].record(),
                                 dict(unsettled, state="failed"))
                unsent = h2.Reading(h2.NOT_STARTED, "none", None, {"request": mine})
                self.assertEqual(h2.transition(before, unsent)[0].record(),
                                 dict(mine, state="failed", code="not_started"))
        for row in h2.TRANSITIONS:
            if row.code in h2.FAULTS.values():
                self.assertEqual((row.states, row.to), (h2.SENDING, "failed"), row)
        self.assertNotIn("failed", h2.FOLLOW)
        # A stop begins at a request that brought no answer, before any binding: by its
        # operation where it named one, else by the list of bindings for its work.
        held = {"held": {"binding_id": "binding_older"}}
        next_named = dict(held, request={"request_id": "request-next", "operation_id": "op_next",
                                         "work_id": "work-next"})
        next_unnamed = dict(held, request={"request_id": "request-next", "work_id": "work-next"})
        onward = (
            (next_named, h2.State("observing_request", request_id="request-next",
                                  operation_id="op_next")),
            (next_unnamed, h2.State("inspecting_request", request_id="request-next",
                                    work_id="work-next")),
            (held, h2.State("releasing", binding_id="binding_older")),
            ({"uncertain": {"binding_id": "binding_older"}},
             h2.State("inspecting_release", binding_id="binding_older")),
        )
        for facts, after in onward:
            self.assertEqual(h2.entering(facts), after)
        # Each observation of a request goes on in those ways: the next request, then
        # the bindings. One that settled it can end the stop in `stopped`; one that
        # did not ends it in `failed`, which names the request.
        for own, states, settles in ((h2.FOUND, h2.ASKING, True),
                                     (h2.NEVER_RAN, h2.ASKING_BY_WAIT, True),
                                     (h2.STILL_OPEN, h2.ASKING, False)):
            for name in states:
                before = sample_state(name)
                for facts, after in onward:
                    with self.subTest(reading=own, state=name, facts=facts):
                        reading = h2.Reading(own, "none", None, dict(facts, unreleased=unsettled))
                        self.assertEqual(h2.transition(before, reading)[0], after)
                last = h2.Reading(own, "none", None, {"unreleased": unsettled})
                self.assertEqual(h2.transition(before, last)[0], h2.State("failed", **unsettled))
                last = h2.Reading(own, "none", None,
                                  {"unreleased": dict(unsettled, operation_id="op_named")})
                self.assertEqual(h2.transition(before, last)[0].record(),
                                 dict(unsettled, state="failed", operation_id="op_named"))
                if settles:
                    after, row = h2.transition(before, h2.Reading(own, "none", None, {}))
                    self.assertEqual((after, row.to), (h2.State("stopped"), "stopped"))
                self.assertEqual(any(row.to == "stopped" for row in h2.TRANSITIONS if row.code == own),
                                 settles)
            self.assertEqual({row.states for row in h2.TRANSITIONS if row.code == own}, {states})
        # A stop that left a request uncertain fails when its last release is answered,
        # and names the request: it never ends in `stopped`.
        for name in h2.RELEASABLE:
            reading = h2.Reading("OK", "none", None, {"code": "OK", "unreleased": unsettled})
            self.assertEqual(h2.transition(sample_state(name), reading)[0],
                             h2.State("failed", **unsettled))
        # Only the observation of a request leads on to a request: a stop observes them
        # all before it asks about a binding. What follows such a state is an
        # observation, and no row leads from one to a state that sends a request.
        self.assertEqual((h2.ASKING_BY_WAIT, h2.ASKING_BY_LIST, h2.ASKING),
                         (("observing_request",), ("inspecting_request",),
                          ("observing_request", "inspecting_request")))
        self.assertEqual([h2.FOLLOW[name] for name in h2.ASKING], [("observe", None), ("work", None)])
        for row in h2.TRANSITIONS:
            if row.to in h2.ASKING:
                self.assertIn(row.code, (h2.FOUND, h2.NEVER_RAN, h2.STILL_OPEN), row)
            if set(row.states) & set(h2.ASKING):
                self.assertEqual(row.states, h2.ASKING_BY_WAIT if row.code == h2.NEVER_RAN else h2.ASKING)
                self.assertIn(row.to, (*h2.ASKING, "releasing", *h2.OBSERVING, "failed", "stopped"), row)
        self.assertFalse({"releasing", *h2.OBSERVING, *h2.ASKING, "failed", "stopped"} & set(h2.SENDING))

    def test_a_call_with_no_answer_keeps_the_binding_it_named(self):
        # M07 W6b: a complete envelope or run record received before the time limit is
        # kept, from typed fields only. The answer itself is still not taken.
        late = "a CLI call ran past its time limit"
        ready = json.dumps({"schema_version": "1", "code": "ACCESS_READY", "data": {},
                            "operation_id": "op_own",
                            "next": {"action": "use_binding", "binding_id": "binding_sample"}})
        reading = h2.no_answer("timed_out", late, ready.encode() + b"\n").reading
        self.assertEqual((reading.code, reading.action, reading.exit), (h2.UNANSWERED, "none", None))
        self.assertEqual((reading.facts["code"], reading.facts["operation_id"],
                          h2.lookup(reading.facts, "next.binding_id")),
                         ("ACCESS_READY", "op_own", "binding_sample"))
        # A line that is not complete names nothing.
        reading = h2.no_answer("timed_out", late, ready.encode()).reading
        self.assertEqual((reading.facts["code"], h2.lookup(reading.facts, "next.binding_id")),
                         (None, None))
        # What the run records of a launch named is kept beside it.
        record = {"binding_id": "binding_sample", "operation_id": "op_sample"}
        reading = h2.no_answer("timed_out", late, b"", record=record).reading
        self.assertEqual((reading.code, reading.facts["record"], reading.facts["code"]),
                         (h2.UNANSWERED, record, None))
        self.assertNotIn("record", h2.no_answer("timed_out", late, b"", record={}).reading.facts)

    def test_a_code_without_its_typed_fields_has_no_row(self):
        reading = h2.Reading("ACCESS_READY", "use_binding", None, {"code": "ACCESS_READY", "next": {}})
        after, row = h2.transition(h2.State("start"), reading)
        self.assertIsNone(row)
        self.assertEqual(after.name, "failed")

    def test_the_call_set_names_no_decision_or_owner_command(self):
        for name, call in h2.load_call_set(["/nonexistent"]).items():
            words = [part for part in call["argv"] if not part.startswith(("{", "-"))]
            self.assertIn(words[0], ("schema", "access", "operation", "run", "inspect"), name)
            for word in words:
                self.assertNotIn(word, ("decision", "approve", "deny", "time", "confirm", "resume",
                                        "allow", "stop", "tui", "setup"), name)
        # `inspect` is read for one subject only: the caller's own bindings, to learn
        # what became of an uncertain release, and of a request that brought no answer.
        self.assertEqual({name: call["argv"] for name, call in h2.load_call_set(["/nonexistent"]).items()
                          if call["argv"][0] == "inspect"},
                         {"bindings": ("inspect", "bindings"), "work": ("inspect", "bindings")})
        # The requests are the calls that carry a request ID, by the command they run.
        self.assertEqual(h2.REQUESTS, {"ensure": "access ensure", "bind": "run"})


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.tree = ast.parse(SOURCE.read_text(encoding="utf-8"), feature_version=(3, 9))

    def test_no_transition_can_read_message_text(self):
        # The planner never names the field that holds an answer's prose.
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node is getattr(self.tree.body[0], "value", None):
                    continue  # the module docstring
                self.assertNotIn("message", node.value.split("."), node.lineno)
                self.assertNotIn(node.value, ("approve", "deny", "yes"), node.lineno)
            if isinstance(node, ast.Attribute):
                self.assertNotEqual(node.attr, "message", node.lineno)

    def test_only_standard_library_imports_and_no_other_harness(self):
        allowed = {"argparse", "collections", "json", "os", "pathlib", "queue", "re",
                   "subprocess", "sys", "threading", "time", "uuid"}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0, node.lineno)
                names = [node.module]
            else:
                continue
            for name in names:
                self.assertIn(name.split(".")[0], allowed, node.lineno)
        text = SOURCE.read_text(encoding="utf-8")
        for word in ("reference-wrapper", "reference_wrapper", "harnesses/cli", "__import__",
                     "importlib", "runpy", "exec(", "eval("):
            self.assertNotIn(word, text)


class WindowsEnvironmentTests(unittest.TestCase):
    def test_windows_environment_uses_only_system_and_fixture_paths(self):
        windows = r"D:\Windows"
        home = r"C:\fixture root\acct"
        inherited = {"PATH": r"C:\extra", "SSH_AUTH_SOCK": "parent-agent"}
        with patch.dict(os.environ, inherited):
            self.assertEqual(h2.windows_launch_variables(windows, home), {
                "SystemRoot": windows,
                "PATH": r"D:\Windows\System32\OpenSSH;D:\Windows\System32;D:\Windows",
                "USERPROFILE": home,
                "ProgramData": home,
                "ALLUSERSPROFILE": home,
                "APPDATA": home,
                "LOCALAPPDATA": home,
                "TEMP": home,
                "TMP": home,
            })
        with self.assertRaisesRegex(h2.PlannerError, "SystemRoot"):
            h2.windows_launch_variables(r"D:Windows", home)


class PlannerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="heimdall-h2-",
                                           dir="/tmp" if os.name == "posix" else None)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        for name in ("acct", "hm", "sshh"):
            (self.root / name).mkdir()
        self.stub = self.root / "heimdall.py"
        self.stub.write_text(STUB, encoding="utf-8")
        self.environment = {"HOME": str(self.root / "acct"), "HEIMDALL_HOME": str(self.root / "hm"),
                            "HEIMDALL_TEST_SSH_HOME": str(self.root / "sshh"),
                            "HEIMDALL_TEST_MGMT_STORE": f"fixture-file:{self.root / 'mgmt-store'}",
                            "HEIMDALL_TEST_IROH_KEY_STORE": str(self.root / "iroh-key-store"),
                            "SSH_AUTH_SOCK": "/nonexistent/parent-agent", "H2_TEST_FOREIGN_ENV": "x"}
        if os.name == "nt":
            self.environment["SystemRoot"] = os.environ["SystemRoot"]
        self.handoffs = []

    def planner(self, mode="normal", handoff=None, environment=None):
        def record(report):
            self.handoffs.append(report)
            return True
        planner = h2.Planner([sys.executable, "-I", "-B", str(self.stub), mode], self.root,
                             self.environment if environment is None else environment,
                             handoff or record)
        self.addCleanup(planner.close)
        return planner

    def calls(self):
        log = self.root / "calls.jsonl"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def path(self, record):
        return [(step["from"], step["code"], step["action"], step["to"])
                for step in record["transitions"]]

    def access(self, profile="covered", **fields):
        return dict({"goal": "access", "profile": profile, "work_id": "work-1"}, **fields)

    def fresh(self):
        """Forget the stub's log and its counts: subtests share one root."""
        for kept in [self.root / "calls.jsonl", *self.root.glob("count-*")]:
            kept.unlink(missing_ok=True)

    def watched(self, seconds=None, limited=(["access", "release"], ["operation", "wait"],
                                             ["inspect", "bindings"])):
        """Every CLI call the harness makes from here on, as its own side sees it: a
        call whose process is ended before it could log itself is seen too. With
        `seconds`, a call about a release has that time limit, or each call that
        begins as one of `limited` does. Returns the commands."""
        seen, run = [], subprocess.run

        def watching(argv, **options):
            command = argv[argv.index("--non-interactive") + 1:]
            seen.append(command)
            if seconds is not None and command[:2] in limited:
                options["timeout"] = seconds
            return run(argv, **options)
        patched = patch.object(h2.subprocess, "run", watching)
        patched.start()
        self.addCleanup(patched.stop)
        return seen

    def holding(self, mode, count):
        """A planner that was given `count` bindings (`binding_many_0` and so on), and
        the release calls it has made since."""
        planner = self.planner(mode)
        for _ in range(count):
            self.assertTrue(h2.run_goal(planner, self.access("many"))["success"])
        self.assertEqual(planner.held, [f"binding_many_{index}" for index in range(count)])
        return planner, lambda: [call[2] for call in self.calls()[count:]]

    def test_discover_reads_the_installed_code_table(self):
        planner = self.planner()
        record = h2.run_goal(planner, {"goal": "discover"})
        self.assertTrue(record["success"], record)
        self.assertEqual(self.path(record), [("start", "OK", "none", "discovered")])
        self.assertEqual(self.calls(), [["schema", "show", "codes"]])
        self.assertGreater(record["discovery_bytes"], 100)
        self.assertEqual((record["calls"], record["round_trips"], record["invalid_retries"]), (1, 1, 0))
        # A later request starts from `discovered`.
        record = h2.run_goal(planner, self.access())
        self.assertEqual(self.path(record), [("discovered", "ACCESS_READY", "use_binding", "ready")])

    def test_discover_fails_when_the_binary_lacks_a_code_the_table_uses(self):
        record = h2.run_goal(self.planner("old-binary"), {"goal": "discover"})
        self.assertFalse(record["success"])
        self.assertIn("PROVIDER_LOCKED", record["detail"])

    def test_the_first_call_comes_from_the_goal(self):
        record = h2.run_goal(self.planner(), self.access())
        self.assertTrue(record["success"], record)
        self.assertEqual(record["final_state"], {"state": "ready", "binding_id": "binding_fixture"})
        calls = self.calls()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:6], ["access", "ensure", "--profile", "covered", "--work-id", "work-1"])

    def test_a_caller_timeout_is_recovered_by_observing(self):
        record = h2.run_goal(self.planner(), self.access(timeout_ms=1))
        self.assertTrue(record["success"], record)
        self.assertEqual(self.path(record), [("start", "ACCEPTED", "observe", "observing"),
                                             ("observing", "ACCESS_READY", "none", "ready")])
        calls = self.calls()
        self.assertEqual(calls[0][-2:], ["--timeout-ms", "1"])
        self.assertEqual(calls[1], ["operation", "wait", "op_fixture", "--timeout-ms", "20000"])
        self.assertEqual(len(calls), 2)  # the request itself is never repeated

    def test_an_approval_is_handed_off_once_then_observed(self):
        for mode, code, action in (("normal", "INTERACTION_REQUIRED", "interact"),
                                   ("approval-code", "APPROVAL_REQUIRED", "observe")):
            with self.subTest(mode=mode):
                self.handoffs.clear()
                record = h2.run_goal(self.planner(mode), self.access("wider", pairs=["h3:deploy"]))
                self.assertTrue(record["success"], record)
                self.assertEqual(self.path(record), [
                    ("start", code, action, "pending_approval"),
                    ("pending_approval", "ACCESS_READY", "none", "ready")])
                self.assertEqual(self.handoffs, [{"handoff": "approval", "decision_ref": "dec_fixture",
                                                  "operation_id": "op_fixture"}])
                self.assertEqual((record["human_handoffs"], record["calls"]), (1, 2))

    def test_a_still_pending_approval_is_observed_again_without_a_second_handoff(self):
        record = h2.run_goal(self.planner("still-pending"), self.access("wider", pairs=["h3:deploy"]))
        self.assertTrue(record["success"], record)
        self.assertEqual([step["to"] for step in record["transitions"]],
                         ["pending_approval", "pending_approval", "ready"])
        self.assertEqual((record["human_handoffs"], record["calls"]), (1, 3))
        commands = [call[:2] for call in self.calls()]
        self.assertEqual(commands, [["access", "ensure"], ["operation", "wait"], ["operation", "wait"]])

    def test_observing_is_bounded(self):
        record = h2.run_goal(self.planner("never"), self.access("wider", pairs=["h3:deploy"]))
        self.assertFalse(record["success"])
        self.assertEqual(record["calls"], h2.MAX_STEPS)
        self.assertEqual(record["final_state"]["state"], "pending_approval")
        self.assertEqual(record["human_handoffs"], 1)
        # The step limit has a row only for an uncertain outcome: here the state is kept.
        self.assertEqual(record["detail"], "the goal was not met within the step limit")
        self.assertEqual(len(record["transitions"]), h2.MAX_STEPS)

    def test_the_human_step_is_excluded_from_wall_time(self):
        def slow(report):
            time.sleep(0.4)
            return True
        started = time.monotonic()
        record = h2.run_goal(self.planner(handoff=slow), self.access("wider", pairs=["h3:deploy"]))
        total = (time.monotonic() - started) * 1000
        self.assertTrue(record["success"], record)
        self.assertLessEqual(record["wall_time_ms"], total - 390)

    def test_a_handoff_the_person_abandons_ends_the_goal(self):
        record = h2.run_goal(self.planner(handoff=lambda report: False),
                             self.access("wider", pairs=["h3:deploy"]))
        self.assertFalse(record["success"])
        self.assertEqual(record["calls"], 1)
        self.assertEqual(record["final_state"]["state"], "pending_approval")

    def test_a_denied_approval_is_a_reported_failure(self):
        record = h2.run_goal(self.planner("denied"), self.access("wider", pairs=["h3:deploy"]))
        self.assertFalse(record["success"])
        self.assertEqual(record["detail"], "failed: CAPABILITY_UNAVAILABLE")
        self.assertEqual(record["final_state"], {"state": "failed", "code": "CAPABILITY_UNAVAILABLE"})
        self.assertTrue(record["transitions"][-1]["by_table"])

    def test_an_operation_that_is_still_going_is_not_read_as_ended(self):
        # M07-W5-R02, away from a release: the view says `running` and carries
        # `ACCESS_READY` with a binding. Nothing is ready, and nothing is held.
        record = h2.run_goal(self.planner("ready-while-running"), self.access(timeout_ms=1))
        self.assertFalse(record["success"])
        self.assertEqual(record["final_state"], {"state": "inconsistent", "code": "OK", "exit_code": 0})
        self.assertEqual(record["detail"], "exit 0 does not fit an operation that is running: "
                                           "its documented exit class is 5")
        self.assertEqual((record["calls"], record["held"]), (2, []))

    def test_an_answer_about_another_operation_is_not_used(self):
        record = h2.run_goal(self.planner("other-operation"), self.access(timeout_ms=1))
        self.assertFalse(record["success"])
        self.assertEqual(record["final_state"]["state"], "observing")
        self.assertEqual(record["calls"], 2)

    def test_a_provider_wait_is_reported_then_requested_once_more(self):
        record = h2.run_goal(self.planner(), self.access("locked"))
        self.assertTrue(record["success"], record)
        self.assertEqual(self.path(record), [
            ("start", "PROVIDER_LOCKED", "interact", "pending_provider"),
            ("pending_provider", "ACCESS_READY", "use_binding", "ready")])
        self.assertEqual(self.handoffs, [{"handoff": "provider", "provider": "fixture_provider",
                                          "kind": "provider_unlock"}])
        first, second = self.calls()
        self.assertEqual(first[:6], second[:6])
        self.assertNotEqual(first[7], second[7])  # a new request, so a new request ID

    def test_a_provider_that_asks_twice_ends_the_goal(self):
        record = h2.run_goal(self.planner("locked-twice"), self.access("locked"))
        self.assertFalse(record["success"])
        self.assertEqual((record["calls"], record["human_handoffs"]), (2, 1))
        self.assertEqual(record["final_state"], {"state": "failed", "code": "PROVIDER_LOCKED"})

    def test_the_capability_refusal_is_recorded_and_ends_cleanly(self):
        goal = self.access(require_unattended=True, expect_refusal="CAPABILITY_UNAVAILABLE")
        record = h2.run_goal(self.planner(), goal)
        self.assertTrue(record["success"], record)
        self.assertEqual(record["detail"], "CAPABILITY_UNAVAILABLE (effect none)")
        self.assertEqual(record["final_state"], {"state": "failed", "code": "CAPABILITY_UNAVAILABLE"})
        self.assertEqual((record["calls"], record["invalid_retries"]), (1, 0))
        self.assertEqual(self.calls()[0][-1], "--require-unattended")
        # The same refusal is a failure when the goal did not expect it, or it had an effect.
        record = h2.run_goal(self.planner(), self.access(require_unattended=True))
        self.assertFalse(record["success"])
        record = h2.run_goal(self.planner("effect"), goal)
        self.assertFalse(record["success"])
        self.assertIn("effect", record["detail"])
        # And an expected refusal that does not come is a failure too.
        record = h2.run_goal(self.planner(), self.access(expect_refusal="CAPABILITY_UNAVAILABLE"))
        self.assertFalse(record["success"])
        self.assertIn("reached ready", record["detail"])

    def test_an_unknown_code_is_a_failure_without_a_retry(self):
        record = h2.run_goal(self.planner(), self.access("novel"))
        self.assertFalse(record["success"])
        self.assertEqual(record["detail"], "unknown code SOMETHING_NEW")
        self.assertEqual(record["final_state"], {"state": "failed", "code": "SOMETHING_NEW"})
        self.assertFalse(record["transitions"][0]["by_table"])
        self.assertEqual(len(self.calls()), 1)

    def test_a_known_code_with_an_unpaired_action_or_bad_field_is_a_failure(self):
        record = h2.run_goal(self.planner(), self.access("odd"))
        self.assertFalse(record["success"])
        self.assertIn("no transition from start for ACCESS_READY", record["detail"])
        record = h2.run_goal(self.planner(), self.access("bad-binding"))
        self.assertFalse(record["success"])
        self.assertIn("invalid binding_id", record["detail"])
        self.assertEqual(len(self.calls()), 2)

    def test_an_invalid_request_is_counted_and_not_retried(self):
        record = h2.run_goal(self.planner(), self.access("missing"))
        self.assertFalse(record["success"])
        self.assertEqual((record["calls"], record["invalid_retries"]), (1, 1))

    def test_an_uncertain_outcome_is_observed_until_its_operation_ends(self):
        wait = ["operation", "wait", "op_fixture", "--timeout-ms", "20000"]
        ready = {"state": "ready", "binding_id": "binding_fixture"}
        stay = ("reconciling", "OK", "observe", "reconciling")
        # (mode, observations made, how the last one ends, the final state)
        cases = (
            ("normal", 1, ("reconciling", "ACCESS_READY", "none", "ready"), ready),
            ("still-pending", 2, ("reconciling", "ACCESS_READY", "none", "ready"), ready),
            # the operation ends at the last observation the step limit allows
            (f"unfinished-{h2.MAX_STEPS - 2}", h2.MAX_STEPS - 1,
             ("reconciling", "ACCESS_READY", "none", "ready"), ready),
            # the operation's own outcome is unknown: the failure names that operation
            ("still-unknown", 1, ("reconciling", "OUTCOME_UNKNOWN", "none", "failed"),
             {"state": "failed", "code": "OUTCOME_UNKNOWN", "operation_id": "op_fixture"}),
            ("denied", 1, ("reconciling", "CAPABILITY_UNAVAILABLE", "none", "failed"),
             {"state": "failed", "code": "CAPABILITY_UNAVAILABLE"}),
        )
        for mode, observations, last, final in cases:
            with self.subTest(mode=mode):
                seen = len(self.calls())
                (self.root / "count-wait").unlink(missing_ok=True)  # the stub's count, per case
                record = h2.run_goal(self.planner(mode), self.access("uncertain"))
                self.assertEqual(record["success"], final is ready, record)
                self.assertEqual(self.path(record), [
                    ("start", "OUTCOME_UNKNOWN", "reconcile", "reconciling"),
                    *[stay] * (observations - 1), last])
                self.assertTrue(all(step["by_table"] for step in record["transitions"]))
                self.assertEqual(record["final_state"], final)
                if final is not ready:
                    self.assertEqual(record["detail"], f"failed: {final['code']}")
                # One request, then only observations of its operation: however many of
                # them it takes, the request is never sent again.
                calls = self.calls()[seen:]
                self.assertEqual([call[:2] for call in calls],
                                 [["access", "ensure"]] + [["operation", "wait"]] * observations)
                self.assertEqual(calls[1:], [wait] * observations)
                self.assertEqual((record["calls"], record["human_handoffs"], record["invalid_retries"]),
                                 (1 + observations, 0, 0))

    def test_an_operation_unfinished_at_the_step_limit_is_reported_with_its_id(self):
        wait = ["operation", "wait", "op_fixture", "--timeout-ms", "20000"]
        for limit in (h2.MAX_STEPS, 3):  # the limit is the goal's own: there is no other
            with self.subTest(limit=limit), patch.object(h2, "MAX_STEPS", limit):
                seen = len(self.calls())
                planner = self.planner("never")
                record = h2.run_goal(planner, self.access("uncertain"))
                self.assertFalse(record["success"])
                # The typed report: the code and the operation, in the final state.
                self.assertEqual(record["final_state"], {"state": "unresolved", "code": "OUTCOME_UNKNOWN",
                                                         "operation_id": "op_fixture"})
                self.assertEqual(self.path(record), [
                    ("start", "OUTCOME_UNKNOWN", "reconcile", "reconciling"),
                    *[("reconciling", "OK", "observe", "reconciling")] * (limit - 1),
                    ("reconciling", h2.BOUND, "none", "unresolved")])
                self.assertTrue(all(step["by_table"] for step in record["transitions"]))
                self.assertIn("step limit", record["detail"])
                # The request once, then observations up to the limit. Nothing else is sent,
                # and the limit itself costs no call.
                calls = self.calls()[seen:]
                self.assertEqual([call[:2] for call in calls],
                                 [["access", "ensure"]] + [["operation", "wait"]] * (limit - 1))
                self.assertEqual(calls[1:], [wait] * (limit - 1))
                self.assertEqual((record["calls"], record["human_handoffs"], record["invalid_retries"],
                                  record["held"]), (limit, 0, 0, []))
                # Nothing is held, so there is nothing to stop; a later goal is a new request.
                self.assertFalse(h2.run_goal(planner, {"goal": "stop"})["success"])
                self.assertEqual(len(self.calls()), seen + limit)

    def test_an_uncertain_outcome_that_names_no_operation_is_reported_without_another_call(self):
        record = h2.run_goal(self.planner(), self.access("uncertain-unnamed"))
        self.assertFalse(record["success"])
        self.assertEqual(self.path(record), [("start", "OUTCOME_UNKNOWN", "reconcile", "failed")])
        self.assertTrue(record["transitions"][0]["by_table"])
        self.assertEqual(record["final_state"], {"state": "failed", "code": "OUTCOME_UNKNOWN"})
        self.assertEqual(len(self.calls()), 1)
        # Its `next` names none but the envelope carries its own: reported with it, and
        # still without another call.
        record = h2.run_goal(self.planner(), self.access("uncertain-unlinked"))
        self.assertFalse(record["success"])
        self.assertEqual(self.path(record), [("start", "OUTCOME_UNKNOWN", "reconcile", "failed")])
        self.assertTrue(record["transitions"][0]["by_table"])
        self.assertEqual(record["final_state"], {"state": "failed", "code": "OUTCOME_UNKNOWN",
                                                 "operation_id": "op_fixture"})
        self.assertEqual(len(self.calls()), 2)

    def test_an_observed_operation_whose_outcome_is_unknown_is_reported_with_its_id(self):
        # Not an uncertain answer to the request: the accepted operation itself ends unknown.
        record = h2.run_goal(self.planner("still-unknown"), self.access(timeout_ms=1))
        self.assertFalse(record["success"])
        self.assertEqual(self.path(record), [("start", "ACCEPTED", "observe", "observing"),
                                             ("observing", "OUTCOME_UNKNOWN", "none", "failed")])
        self.assertEqual(record["final_state"], {"state": "failed", "code": "OUTCOME_UNKNOWN",
                                                 "operation_id": "op_fixture"})
        self.assertEqual(record["detail"], "failed: OUTCOME_UNKNOWN")

    def test_an_exit_class_that_does_not_fit_its_answer_fails_the_goal(self):
        inconsistent = lambda code, status: {"state": "inconsistent", "code": code, "exit_code": status}
        # M07-W3-R03's probe: the successful ensure, its usual envelope, exit 1.
        planner = self.planner("exit:ACCESS_READY=1")
        record = h2.run_goal(planner, self.access())
        self.assertFalse(record["success"], record)
        self.assertEqual(record["final_state"], inconsistent("ACCESS_READY", 1))
        self.assertEqual(self.path(record), [("start", h2.MISMATCH, "none", "inconsistent")])
        self.assertTrue(record["transitions"][0]["by_table"])
        self.assertEqual(record["detail"], "exit 1 does not fit ACCESS_READY: its documented exit class is 0")
        self.assertEqual((record["calls"], len(self.calls())), (1, 1))  # nothing is tried again
        # The binding that answer named is held all the same, so a stop releases it.
        self.assertEqual(record["held"], ["binding_fixture"])
        stopped = h2.run_goal(planner, {"goal": "stop"})
        self.assertTrue(stopped["success"], stopped)
        self.assertEqual(self.path(stopped), [("releasing", "OK", "none", "stopped")])
        self.assertEqual((stopped["held"], self.calls()[1:]), ([], [["access", "release", "binding_fixture"]]))
        # Every other kind of call:
        # (mode, goal, the code whose exit is wrong, that exit, calls made, what is held after)
        refusal = self.access(require_unattended=True, expect_refusal="CAPABILITY_UNAVAILABLE")
        cases = (
            ("exit:OK=1", {"goal": "discover"}, "OK", 1, 1, []),
            ("exit:ACCEPTED=0", self.access(timeout_ms=1), "ACCEPTED", 0, 1, []),  # the bounded wait
            # the observation: it found the operation ended, and its binding is held
            ("exit:OK=5", self.access(timeout_ms=1), "ACCESS_READY", 5, 2, ["binding_fixture"]),
            ("exit:OUTCOME_UNKNOWN=0", self.access("uncertain"), "OUTCOME_UNKNOWN", 0, 1, []),
            ("exit:CAPABILITY_UNAVAILABLE=0", refusal, "CAPABILITY_UNAVAILABLE", 0, 1, []),
            ("exit:INTERACTION_REQUIRED=4", self.access("wider", pairs=["h3:deploy"]),
             "INTERACTION_REQUIRED", 4, 1, []),
            ("refused-launch-exit-0", {"goal": "run", "profile": "covered", "work_id": "work-8",
                                       "argv": [str(self.stub)]}, "CAPABILITY_UNAVAILABLE", 0, 1, []),
        )
        for mode, goal, code, status, calls, held in cases:
            with self.subTest(mode=mode, goal=goal["goal"]):
                self.handoffs.clear()
                record = h2.run_goal(self.planner(mode), goal)
                self.assertFalse(record["success"], record)
                self.assertEqual(record["final_state"], inconsistent(code, status))
                self.assertEqual(record["transitions"][-1]["code"], h2.MISMATCH)
                self.assertTrue(all(step["by_table"] for step in record["transitions"]))
                self.assertEqual((record["calls"], self.handoffs, record["held"]), (calls, [], held))

    def test_prose_never_changes_a_transition(self):
        goals = [{"goal": "discover"}, self.access(), self.access(timeout_ms=1),
                 self.access("wider", pairs=["h3:deploy"]), self.access("uncertain"),
                 self.access(require_unattended=True, expect_refusal="CAPABILITY_UNAVAILABLE")]
        plain, lying = self.planner(), self.planner("lying")
        for goal in goals:
            with self.subTest(goal=goal):
                honest = h2.run_goal(plain, dict(goal))
                misled = h2.run_goal(lying, dict(goal))
                self.assertTrue(honest["success"], honest)
                self.assertEqual(self.path(honest), self.path(misled))
                self.assertEqual(honest["final_state"], misled["final_state"])
                self.assertEqual(honest["detail"], misled["detail"])

    def test_run_then_stop_holds_and_ends_its_own_child(self):
        planner = self.planner()
        child = [str(self.stub), "fixture-argument"]
        ready = h2.run_goal(planner, self.access())
        running = h2.run_goal(planner, {"goal": "run", "profile": "covered", "work_id": "work-1",
                                        "argv": child})
        self.assertTrue(running["success"], running)
        self.assertEqual(self.path(running), [("ready", "launching", "none", "running")])
        state = running["final_state"]
        self.assertEqual((state["state"], state["binding_id"]), ("running", "binding_fixture"))
        self.assertEqual(state["pid"], planner.child.process.pid)
        self.assertIsNone(planner.child.process.poll())
        ensure, launch = self.calls()
        self.assertEqual((ensure[6], launch[5]), ("--request-id", "--request-id"))
        self.assertNotEqual(ensure[7], launch[6])  # the launch is a request of its own
        self.assertEqual((ensure[3], ensure[5]), (launch[2], launch[4]))  # for the same work
        self.assertEqual(launch[9:], ["--", *child])
        self.assertEqual((ready["held"], running["held"]), (["binding_fixture"], ["binding_fixture"]))
        self.assertEqual(list(self.root.glob("h2-run-*")), [])
        process = planner.child.process
        stopped = h2.run_goal(planner, {"goal": "stop"})
        self.assertTrue(stopped["success"], stopped)
        self.assertEqual(self.path(stopped), [("running", "OK", "none", "stopped")])
        self.assertEqual(stopped["child_exit_code"], 0)
        self.assertEqual(process.returncode, 0)
        self.assertIsNone(planner.child)
        self.assertEqual(self.calls()[2:], [["access", "release", "binding_fixture"]])
        self.assertEqual(stopped["held"], [])
        self.assertTrue(ready["success"])

    def test_a_launch_under_a_second_binding_is_stopped_by_releasing_both(self):
        # The launch's run record may name a binding other than the one prepared for the
        # same work. Both are held, and the stop releases each one once, the newest first.
        planner = self.planner("second-binding")
        self.assertTrue(h2.run_goal(planner, self.access())["success"])
        running = h2.run_goal(planner, {"goal": "run", "profile": "covered", "work_id": "work-1",
                                        "argv": [str(self.stub)]})
        self.assertTrue(running["success"], running)
        self.assertEqual(self.path(running), [("ready", "launching", "none", "running")])
        self.assertEqual(running["final_state"]["binding_id"], "binding_second")
        self.assertEqual(running["held"], ["binding_fixture", "binding_second"])
        process = planner.child.process
        stopped = h2.run_goal(planner, {"goal": "stop"})
        self.assertTrue(stopped["success"], stopped)
        self.assertEqual(self.path(stopped), [("running", "OK", "none", "releasing"),
                                              ("releasing", "OK", "none", "stopped")])
        self.assertTrue(all(step["by_table"] for step in stopped["transitions"]))
        self.assertEqual(self.calls()[2:], [["access", "release", "binding_second"],
                                            ["access", "release", "binding_fixture"]])
        self.assertEqual((stopped["calls"], stopped["held"], stopped["child_exit_code"]), (2, [], 0))
        self.assertEqual(process.returncode, 0)
        self.assertFalse(h2.run_goal(planner, {"goal": "stop"})["success"])  # nothing held now
        self.assertEqual(len(self.calls()), 4)

    def test_a_stop_after_a_failed_goal_releases_what_is_held(self):
        # M07-W3-R01, first probe: access is given, a later goal fails, then stop.
        planner = self.planner()
        self.assertTrue(h2.run_goal(planner, self.access())["success"])
        failed = h2.run_goal(planner, self.access("novel"))
        self.assertEqual((failed["success"], failed["final_state"]["state"], failed["held"]),
                         (False, "failed", ["binding_fixture"]))
        stopped = h2.run_goal(planner, {"goal": "stop"})
        self.assertTrue(stopped["success"], stopped)
        self.assertEqual(self.path(stopped), [("releasing", "OK", "none", "stopped")])
        self.assertTrue(stopped["transitions"][0]["by_table"])
        self.assertEqual((stopped["calls"], stopped["held"]), (1, []))
        self.assertEqual(self.calls()[2:], [["access", "release", "binding_fixture"]])
        self.assertFalse(h2.run_goal(planner, {"goal": "stop"})["success"])  # nothing held now
        self.assertEqual(len(self.calls()), 3)

    def test_close_releases_what_is_held_and_ends_the_child(self):
        # M07-W3-R01, second probe: close() with held bindings, here two and a running child.
        planner = self.planner("second-binding")
        self.assertTrue(h2.run_goal(planner, self.access())["success"])
        self.assertTrue(h2.run_goal(planner, {"goal": "run", "profile": "covered", "work_id": "work-1",
                                              "argv": [str(self.stub)]})["success"])
        process = planner.child.process
        closing = planner.close()
        self.assertEqual(self.calls()[2:], [["access", "release", "binding_second"],
                                            ["access", "release", "binding_fixture"]])
        self.assertEqual((planner.held, planner.child, process.returncode), ([], None, 0))
        self.assertEqual(closing, {"released": ["binding_fixture", "binding_second"], "held": []})
        self.assertEqual(planner.close(), {"released": [], "held": []})  # and nothing more is sent
        self.assertEqual(len(self.calls()), 4)
        # After a failed goal too. A release that is not answered as asked ends the attempt
        # with the binding still reported: close never loops.
        for mode, left in (("normal", []), ("other-binding", ["binding_fixture"])):
            with self.subTest(mode=mode):
                planner = self.planner(mode)
                self.assertTrue(h2.run_goal(planner, self.access())["success"])
                self.assertFalse(h2.run_goal(planner, self.access("novel"))["success"])
                seen = len(self.calls())
                self.assertEqual(planner.close()["held"], left)
                self.assertEqual(self.calls()[seen:], [["access", "release", "binding_fixture"]])

    def test_a_stop_the_step_limit_cut_short_is_finished_by_the_next_stop(self):
        # M07-W3-R01, third probe: one binding more than a stop can release within its limit.
        planner = self.planner()
        held = [f"binding_many_{index}" for index in range(h2.MAX_STEPS + 1)]
        for index in range(len(held)):
            record = h2.run_goal(planner, self.access("many"))
            self.assertTrue(record["success"], record)
        self.assertEqual(record["held"], held)
        first = h2.run_goal(planner, {"goal": "stop"})
        self.assertFalse(first["success"])
        self.assertIn("step limit", first["detail"])
        self.assertEqual((first["calls"], first["held"]), (h2.MAX_STEPS, held[:1]))
        self.assertEqual(first["final_state"], {"state": "releasing", "binding_id": held[0]})
        second = h2.run_goal(planner, {"goal": "stop"})
        self.assertTrue(second["success"], second)
        self.assertEqual(self.path(second), [("releasing", "OK", "none", "stopped")])
        self.assertEqual((second["calls"], second["held"]), (1, []))
        # Each binding was released once, the newest first.
        self.assertEqual(self.calls()[len(held):], [["access", "release", binding]
                                                    for binding in reversed(held)])

    def test_a_refused_release_is_recorded_and_the_rest_are_still_released(self):
        many = "binding_many_{}".format
        refusal = lambda index, code="CAPABILITY_UNAVAILABLE", status=4: {
            "binding_id": many(index), "code": code, "exit_code": status}
        # (the bindings refused, the refusal the stop's final state names)
        for named, first in (("1", 1),    # the middle one
                             ("0", 0),    # the last one asked for
                             ("2", 2),    # the first one asked for
                             ("*", 2)):   # every one
            with self.subTest(refused=named):
                for name in ("calls.jsonl", "count-many"):
                    (self.root / name).unlink(missing_ok=True)
                refused = [2, 1, 0] if named == "*" else [int(named)]
                mode = "refuse:" + ("*" if named == "*" else many(named))
                planner, released = self.holding(mode, 3)
                stopped = h2.run_goal(planner, {"goal": "stop"})
                # Each binding was asked for once, the newest first, whatever was refused.
                self.assertEqual(released(), [many(2), many(1), many(0)])
                # One step for each: the stop goes on after a refusal, and fails at its end.
                path = [("ready" if asked == 2 else "releasing",
                         *((h2.REFUSED, "none") if asked in refused else ("OK", "none")),
                         "releasing" if asked else "failed") for asked in (2, 1, 0)]
                self.assertEqual(self.path(stopped), path)
                self.assertTrue(all(step["by_table"] for step in stopped["transitions"]))
                self.assertEqual(stopped["refused_releases"], [refusal(index) for index in refused])
                self.assertEqual(stopped["held"], [many(index) for index in sorted(refused)])
                self.assertEqual(stopped["final_state"], dict(refusal(first), state="failed"))
                self.assertEqual((stopped["success"], stopped["calls"], stopped["detail"]),
                                 (False, 3, "failed: CAPABILITY_UNAVAILABLE"))
                self.assertEqual(planner.refusals, stopped["refused_releases"])
        # Whatever the code of the refusal: a binding Heimdall does not know (counted as a
        # wrong request too), and a code no table has.
        for kind, code, status, invalid in (("refuse-unknown", "NOT_FOUND", 2, 1),
                                            ("refuse-novel", "SOMETHING_NEW", 1, 0)):
            with self.subTest(kind=kind):
                for name in ("calls.jsonl", "count-many"):
                    (self.root / name).unlink(missing_ok=True)
                planner, released = self.holding(f"{kind}:{many(1)}", 3)
                stopped = h2.run_goal(planner, {"goal": "stop"})
                self.assertEqual(released(), [many(2), many(1), many(0)])
                self.assertEqual(stopped["refused_releases"], [refusal(1, code, status)])
                self.assertEqual((stopped["success"], stopped["held"], stopped["invalid_retries"]),
                                 (False, [many(1)], invalid))

    def test_a_release_in_the_wrong_exit_class_is_recorded_as_a_refusal_and_the_rest_are_released(self):
        many = "binding_many_{}".format
        defect = "exit {} does not fit {}: its documented exit class is {}; a probable product defect"
        planner, released = self.holding("refuse-exit-0:" + many(1), 3)
        stopped = h2.run_goal(planner, {"goal": "stop"})
        entry = {"binding_id": many(1), "code": "CAPABILITY_UNAVAILABLE", "exit_code": 0,
                 "inconsistent": True, "detail": defect.format(0, "CAPABILITY_UNAVAILABLE", 4)}
        # The stop goes on: each binding was asked for once, the newest first.
        self.assertEqual(released(), [many(2), many(1), many(0)])
        self.assertEqual(self.path(stopped), [("ready", "OK", "none", "releasing"),
                                              ("releasing", h2.REFUSED, "none", "releasing"),
                                              ("releasing", "OK", "none", "failed")])
        self.assertTrue(all(step["by_table"] for step in stopped["transitions"]))
        self.assertEqual((stopped["refused_releases"], stopped["outcome_unknown"], stopped["held"]),
                         ([entry], [], [many(1)]))
        self.assertEqual(stopped["final_state"],
                         {"state": "failed", "code": "CAPABILITY_UNAVAILABLE",
                          "binding_id": many(1), "exit_code": 0})
        # The record names it as a probable product defect.
        self.assertEqual((stopped["success"], stopped["detail"]), (False, entry["detail"]))
        self.assertEqual(planner.by_binding(), {many(1): {"held": True, "attempts": [
            {"by": "stop", "outcome": "refused", "code": "CAPABILITY_UNAVAILABLE", "exit_code": 0,
             "inconsistent": True, "detail": entry["detail"]}]}})
        # `OK` in the wrong exit class: the binding stays held, and the next is still asked for.
        self.fresh()
        planner, released = self.holding("exit:OK=1", 2)
        stopped = h2.run_goal(planner, {"goal": "stop"})
        self.assertEqual(released(), [many(1), many(0)])
        self.assertEqual(stopped["refused_releases"], [
            {"binding_id": many(index), "code": "OK", "exit_code": 1, "inconsistent": True,
             "detail": defect.format(1, "OK", 0)} for index in (1, 0)])
        self.assertEqual((stopped["success"], stopped["held"], stopped["detail"]),
                         (False, [many(0), many(1)], defect.format(1, "OK", 0)))
        self.assertEqual(stopped["final_state"], {"state": "failed", "code": "OK",
                                                  "binding_id": many(1), "exit_code": 1})
        # M07-W5-R03's probe: a published code the transition table does not act on,
        # `SERVICE_UNAVAILABLE` (class 5) with exit 0, in a stop and then in the close.
        self.fresh()
        planner, released = self.holding("refuse-unavailable-exit-0:" + many(1), 3)
        stopped = h2.run_goal(planner, {"goal": "stop"})
        entry = {"binding_id": many(1), "code": "SERVICE_UNAVAILABLE", "exit_code": 0,
                 "inconsistent": True, "detail": defect.format(0, "SERVICE_UNAVAILABLE", 5)}
        self.assertEqual((stopped["refused_releases"], stopped["held"], stopped["detail"]),
                         ([entry], [many(1)], entry["detail"]))
        self.assertEqual(planner.close(), {"released": [], "held": [many(1)]})
        self.assertEqual(released(), [many(2), many(1), many(0), many(1)])
        attempt = {key: value for key, value in entry.items() if key != "binding_id"}
        self.assertEqual(planner.by_binding(), {many(1): {"held": True, "attempts": [
            dict(attempt, by=by, outcome="refused") for by in ("stop", "close")]}})
        # The class checked is the installed table's own where discovery read it: here
        # for a code the frozen table lacks. Without discovery that code has no
        # documented class, and its refusal is recorded with the exit status it came with.
        for discovered in (False, True):
            with self.subTest(discovered=discovered):
                self.fresh()
                planner = self.planner("refuse-installed:" + many(0))
                if discovered:
                    self.assertTrue(h2.run_goal(planner, {"goal": "discover"})["success"])
                self.assertTrue(h2.run_goal(planner, self.access("many"))["success"])
                stopped = h2.run_goal(planner, {"goal": "stop"})
                self.assertEqual(stopped["refused_releases"], [dict(
                    {"binding_id": many(0), "code": "ONLY_INSTALLED", "exit_code": 1},
                    **({"inconsistent": True, "detail": defect.format(1, "ONLY_INSTALLED", 6)}
                       if discovered else {}))])
        # An uncertain answer in the wrong exit class is still uncertain, not a refusal:
        # a later stop observes it and sends nothing. The list says the binding is
        # `active`, which is no evidence that the release never ran.
        self.fresh()
        planner, _ = self.holding(f"uncertain:{many(1)}:bindings:active:0", 3)
        stopped = h2.run_goal(planner, {"goal": "stop"})
        self.assertEqual((stopped["refused_releases"], stopped["held"]), ([], [many(1)]))
        self.assertEqual(stopped["outcome_unknown"], [
            {"binding_id": many(1), "code": "OUTCOME_UNKNOWN", "exit_code": 0, "request_id": None,
             "inconsistent": True, "detail": defect.format(0, "OUTCOME_UNKNOWN", 7)}])
        seen = len(self.calls())
        later = h2.run_goal(planner, {"goal": "stop"})
        self.assertEqual(self.calls()[seen:], [["inspect", "bindings"]])
        self.assertEqual((later["success"], later["held"], later["refused_releases"]),
                         (False, [many(1)], []))

    def test_an_uncertain_release_is_recorded_apart_and_the_rest_are_still_released(self):
        many = "binding_many_{}".format
        # (how the answer names its operation, the operation the record names)
        for means, operation in (("operation", "op_fixture"), ("own", "op_fixture"),
                                 ("bindings", None)):
            with self.subTest(means=means):
                self.fresh()
                planner, _ = self.holding(f"uncertain:{many(1)}:{means}:unknown", 3)
                stopped = h2.run_goal(planner, {"goal": "stop"})
                named = {"operation_id": operation} if operation else {}
                # Each binding was asked for once, the newest first, and nothing was
                # observed: the stop that gets the uncertain answer goes on to the rest.
                self.assertEqual(self.calls()[3:], [["access", "release", many(index)]
                                                    for index in (2, 1, 0)])
                self.assertEqual(self.path(stopped), [("ready", "OK", "none", "releasing"),
                                                      ("releasing", h2.UNCERTAIN, "none", "releasing"),
                                                      ("releasing", "OK", "none", "failed")])
                self.assertTrue(all(step["by_table"] for step in stopped["transitions"]))
                # Recorded apart from a refusal: the binding, the request ID (the release
                # takes none today) and the operation, when the answer names one.
                self.assertEqual(stopped["refused_releases"], [])
                self.assertEqual(stopped["outcome_unknown"], [dict(
                    {"binding_id": many(1), "code": "OUTCOME_UNKNOWN", "exit_code": 7,
                     "request_id": None}, **named)])
                self.assertEqual(stopped["held"], [many(1)])
                self.assertEqual(stopped["final_state"], dict(
                    {"state": "failed", "code": "OUTCOME_UNKNOWN", "binding_id": many(1),
                     "exit_code": 7}, **named))
                self.assertEqual((stopped["success"], stopped["calls"], stopped["detail"]),
                                 (False, 3, "failed: OUTCOME_UNKNOWN"))
                self.assertEqual(planner.uncertain, {many(1): dict({"request_id": None}, **named)})

    def test_a_later_stop_or_the_close_observes_an_uncertain_release_before_it_sends_anything(self):
        mine = "binding_fixture"
        wait = ["operation", "wait", "op_fixture", "--timeout-ms", "20000"]
        inspect = ["inspect", "bindings"]
        release = ["access", "release", mine]
        # (how the uncertain answer named its operation, what the observation says; the
        #  outcome recorded for it, with the code and exit status it was read from; the
        #  calls made; whether the binding is still held)
        rows = (
            # the operation is observed released: the binding leaves `held`, nothing is sent
            ("operation", "released", "released", "OK", 0, [wait], False),
            ("own", "released", "released", "OK", 0, [wait], False),
            # the operation ended and says the release did not happen: one new release
            # is sent after the observation, and only then
            ("operation", "never-ran", "not_run", "CAPABILITY_UNAVAILABLE", 4, [wait, release], False),
            ("own", "never-ran", "not_run", "CAPABILITY_UNAVAILABLE", 4, [wait, release], False),
            # the operation is unfinished when the wait runs out, or does not say: still
            # unknown, held, and nothing is sent
            ("operation", "unfinished", "still_unknown", "OK", 5, [wait], True),
            ("operation", "unknown", "still_unknown", "OUTCOME_UNKNOWN", 7, [wait], True),
            ("operation", "partial", "still_unknown", "OPERATION_CANCELLED", 4, [wait], True),
            ("operation", "missing", "still_unknown", "NOT_FOUND", 2, [wait], True),
            ("operation", "wrong-exit", "still_unknown", "OK", 3, [wait], True),
            # M07-W5-R02's probe, the reviewer's exact answer: the operation is still
            # `running`, yet answered `OK` with no next action and exit 0. An active
            # operation is no evidence of a release: still unknown, held, nothing sent
            ("operation", "contradictory", "still_unknown", "OK", 0, [wait], True),
            # still `running`, with a refusal's code and no effect: only a terminal
            # view says that the release did not happen, so no new release
            ("operation", "active-refusal", "still_unknown", "OK", 4, [wait], True),
            # it failed, and its own code is `OK`: no release was observed
            ("operation", "ended-badly", "still_unknown", "OK", 0, [wait], True),
            # no operation, and the binding is listed `active`: that alone is no evidence
            # that the release never ran. No new release: still unknown, and held
            ("bindings", "active", "still_unknown", "OK", 0, [inspect], True),
            # no operation, and the complete list does not name the binding: not listed.
            # It is not held, and it is never recorded as released
            ("bindings", "absent", "not_listed", "OK", 0, [inspect], False),
            # no operation, and the list gives the binding the state `released`
            ("bindings", "released", "released", "OK", 0, [inspect], False),
            # no operation, and the list does not say: still unknown, held, nothing sent
            ("bindings", "odd", "still_unknown", "OK", 0, [inspect], True),
            ("bindings", "twice", "still_unknown", "OK", 0, [inspect], True),
            ("bindings", "unknown", "still_unknown", "SERVICE_UNAVAILABLE", 5, [inspect], True),
            ("bindings", "wrong-exit", "still_unknown", "OK", 4, [inspect], True),
        )
        # The state the list gave the binding, where it could be read.
        states = {"active": "active", "absent": h2.ABSENT, "released": "released",
                  "odd": "suspended"}
        for means, says, outcome, code, status, calls, held in rows:
            for by in ("stop", "close"):
                with self.subTest(means=means, says=says, by=by):
                    self.fresh()
                    planner = self.planner(f"uncertain:{mine}:{means}:{says}")
                    self.assertTrue(h2.run_goal(planner, self.access())["success"])
                    first = h2.run_goal(planner, {"goal": "stop"})
                    self.assertEqual((first["success"], first["held"], len(first["outcome_unknown"]),
                                      first["still_unknown"], first["not_listed"]),
                                     (False, [mine], 1, [], []))
                    self.assertEqual(self.calls()[1:], [release])
                    observing = "inspecting_release" if means == "bindings" else "observing_release"
                    named = {} if means == "bindings" else {"operation_id": "op_fixture"}
                    if by == "close":
                        # `released` names only a binding that was released: one that is
                        # not listed is in neither list.
                        self.assertEqual(planner.close(), {
                            "released": [mine] if outcome in ("released", "not_run") else [],
                            "held": [mine] if held else []})
                    else:
                        later = h2.run_goal(planner, {"goal": "stop"})
                        path = {"released": [(observing, h2.OBSERVED, "none", "stopped")],
                                "not_listed": [(observing, h2.NOT_LISTED, "none", "stopped")],
                                "not_run": [(observing, h2.NOT_RUN, "none", "releasing"),
                                            ("releasing", "OK", "none", "stopped")],
                                "still_unknown": [(observing, h2.STILL_UNCERTAIN, "none", "failed")]}
                        self.assertEqual(self.path(later), path[outcome])
                        self.assertTrue(all(step["by_table"] for step in later["transitions"]))
                        # The goal is met when the binding is no longer held: released,
                        # or not listed.
                        self.assertEqual((later["success"], later["held"], later["calls"]),
                                         (not held, [mine] if held else [], len(calls)))
                        # The record lists the observation under its own outcome: an
                        # observation is not a release answered `OUTCOME_UNKNOWN`.
                        self.assertEqual((later["refused_releases"], later["outcome_unknown"]),
                                         ([], []))
                        self.assertEqual([entry["binding_id"] for entry in later["still_unknown"]],
                                         [mine] * (outcome == "still_unknown"))
                        self.assertEqual(later["not_listed"], [
                            {"binding_id": mine, "code": "OK", "exit_code": 0,
                             "observed": "bindings", "state": h2.ABSENT}] * (outcome == "not_listed"))
                        if held:
                            self.assertEqual(later["final_state"], dict(
                                {"state": "failed", "code": "OUTCOME_UNKNOWN", "binding_id": mine,
                                 "exit_code": status}, **named))
                    # The observation comes first. A release follows only where the
                    # operation the uncertain answer named says the first did not happen.
                    self.assertEqual(self.calls()[2:], calls)
                    self.assertEqual(release in calls, means != "bindings" and says == "never-ran")
                    self.assertEqual(planner.held, [mine] if held else [])
                    self.assertEqual(set(planner.uncertain), {mine} if held else set())
                    # The binding's attempts, in order.
                    entry = planner.by_binding()[mine]
                    self.assertEqual(entry["held"], held)
                    observed = "bindings" if means == "bindings" else "operation"
                    self.assertEqual(
                        [(attempt["by"], attempt["outcome"], attempt.get("observed"))
                         for attempt in entry["attempts"]],
                        [("stop", "outcome_unknown", None), (by, outcome, observed)]
                        + [(by, "released", None)] * (outcome == "not_run"))
                    observation = entry["attempts"][1]
                    self.assertEqual((observation["code"], observation["exit_code"]), (code, status))
                    # An answer whose exit class does not fit is recorded as inconsistent:
                    # for an operation still going, that class is the bounded wait's.
                    defects = {"wrong-exit": "exit 3 does not fit OK: its documented exit class is 0",
                               "contradictory": "exit 0 does not fit an operation that is running: "
                                                "its documented exit class is 5",
                               "active-refusal": "exit 4 does not fit an operation that is running: "
                                                 "its documented exit class is 5"}
                    if means == "bindings":
                        defects = {"wrong-exit": "exit 4 does not fit OK: its documented exit class is 0"}
                    self.assertEqual(observation.get("inconsistent", False), says in defects)
                    self.assertEqual(observation.get("detail"),
                                     f"{defects[says]}; a probable product defect" if says in defects
                                     else None)
                    if means == "bindings":
                        self.assertEqual(observation.get("state"),
                                         h2.ABSENT if says == "wrong-exit" else states.get(says))
                    if held:  # still unknown: it names the same request and operation
                        self.assertEqual({key: observation.get(key) for key in ("request_id", *named)},
                                         dict({"request_id": None}, **named))

    def test_an_uncertain_release_is_never_sent_again_while_its_outcome_is_unknown(self):
        many = "binding_many_{}".format
        release = lambda index: ["access", "release", many(index)]
        # The operation is unfinished every time its wait runs out; and, where the
        # answer named none, the list goes on saying that the binding is `active`.
        for means, says, observation, observing in (
                ("operation", "unfinished",
                 ["operation", "wait", "op_fixture", "--timeout-ms", "20000"], "observing_release"),
                ("bindings", "active", ["inspect", "bindings"], "inspecting_release")):
            with self.subTest(means=means):
                self.fresh()
                planner, _ = self.holding(f"uncertain:{many(1)}:{means}:{says}", 3)
                # Three stops, a new binding and its stop, and the close: the release of
                # the uncertain binding is sent once, by the first stop. Each later stop
                # and the close observe it once, and it stays held and reported.
                stops = [h2.run_goal(planner, {"goal": "stop"}) for _ in range(3)]
                self.assertTrue(h2.run_goal(planner, self.access("many"))["success"])
                last = h2.run_goal(planner, {"goal": "stop"})
                closing = planner.close()
                self.assertEqual(self.calls()[3:], [
                    release(2), release(1), release(0), observation, observation,
                    self.calls()[-4], release(3), observation, observation])
                self.assertEqual(self.calls()[-4][:2], ["access", "ensure"])
                self.assertEqual(sum(call == release(1) for call in self.calls()), 1)
                self.assertEqual([(stop["success"], stop["held"]) for stop in stops + [last]],
                                 [(False, [many(1)])] * 4)
                self.assertEqual(self.path(last), [("ready", "OK", "none", observing),
                                                   (observing, h2.STILL_UNCERTAIN, "none", "failed")])
                self.assertEqual([(len(stop["outcome_unknown"]), len(stop["still_unknown"]))
                                  for stop in stops + [last]], [(1, 0)] + [(0, 1)] * 3)
                self.assertEqual(closing, {"released": [], "held": [many(1)]})
                entry = planner.by_binding()
                self.assertEqual(list(entry), [many(1)])
                self.assertEqual([(attempt["by"], attempt["outcome"], "observed" in attempt)
                                  for attempt in entry[many(1)]["attempts"]],
                                 [("stop", "outcome_unknown", False)]
                                 + [("stop", "still_unknown", True)] * 3
                                 + [("close", "still_unknown", True)])

    def test_the_close_does_not_observe_an_uncertain_release_of_its_own(self):
        many = "binding_many_{}".format
        planner, _ = self.holding(f"uncertain:{many(1)}:operation:released", 3)
        closing = planner.close()
        # The close got the uncertain answer itself: it goes on to the rest and ends.
        self.assertEqual(self.calls()[3:], [["access", "release", many(index)] for index in (2, 1, 0)])
        self.assertEqual(closing, {"released": [many(0), many(2)], "held": [many(1)]})
        self.assertEqual(planner.by_binding(), {many(1): {"held": True, "attempts": [
            {"by": "close", "outcome": "outcome_unknown", "code": "OUTCOME_UNKNOWN", "exit_code": 7,
             "request_id": None, "operation_id": "op_fixture"}]}})
        # A later close is a stop of its own: it observes first, and here finds it released.
        self.assertEqual(planner.close(), {"released": [many(1)], "held": []})
        self.assertEqual(self.calls()[6:], [["operation", "wait", "op_fixture", "--timeout-ms", "20000"]])

    def test_the_close_asks_again_after_a_stop_that_was_cut_short(self):
        many = "binding_many_{}".format
        count = h2.MAX_STEPS + 2
        planner, released = self.holding("refuse:" + many(count - 1), count)
        first = h2.run_goal(planner, {"goal": "stop"})
        self.assertIn("step limit", first["detail"])
        self.assertEqual(first["final_state"], {"state": "releasing", "binding_id": many(1)})
        # The close is a stop of its own, whatever state the goals left: it asks about
        # every held binding, the one the stop was refused included.
        closing = planner.close()
        self.assertEqual(released()[h2.MAX_STEPS:], [many(1), many(count - 1), many(0)])
        self.assertEqual(closing, {"released": [many(0), many(1)], "held": [many(count - 1)]})
        refused = {"outcome": "refused", "code": "CAPABILITY_UNAVAILABLE", "exit_code": 4}
        self.assertEqual(planner.by_binding(), {many(count - 1): {"held": True, "attempts": [
            dict(refused, by="stop"), dict(refused, by="close")]}})

    def test_close_records_a_refused_release_and_still_releases_the_rest(self):
        many = "binding_many_{}".format
        planner, released = self.holding("refuse:" + many(1), 3)
        closing = planner.close()
        self.assertEqual(released(), [many(2), many(1), many(0)])
        self.assertEqual(closing, {"released": [many(0), many(2)], "held": [many(1)]})
        self.assertEqual(planner.refusals, [{"binding_id": many(1), "code": "CAPABILITY_UNAVAILABLE",
                                             "exit_code": 4}])
        self.assertEqual(planner.state.record(), dict(planner.refusals[0], state="failed"))

    def test_refused_releases_never_make_a_stop_or_a_close_spin(self):
        many = "binding_many_{}".format
        count = h2.MAX_STEPS + 2
        newest_first = [many(index) for index in reversed(range(count))]
        # Every release refused, and more bindings than one stop may ask for: the close
        # asks for each once, in two rounds, and ends with all of them held.
        planner, released = self.holding("refuse:*", count)
        closing = planner.close()
        self.assertEqual(released(), newest_first)
        self.assertEqual(closing, {"released": [], "held": newest_first[::-1]})
        self.assertEqual([refusal["binding_id"] for refusal in planner.refusals], newest_first)
        # A stop of its own is a new one: it asks again, within its limit, and fails.
        again = h2.run_goal(planner, {"goal": "stop"})
        self.assertEqual((again["success"], again["calls"], len(again["refused_releases"])),
                         (False, h2.MAX_STEPS, h2.MAX_STEPS))
        self.assertEqual(len(released()), count + h2.MAX_STEPS)

    def test_a_stop_cut_short_after_a_refusal_is_finished_without_asking_again(self):
        many = "binding_many_{}".format
        count = h2.MAX_STEPS + 2
        for name in ("calls.jsonl", "count-many"):
            (self.root / name).unlink(missing_ok=True)
        planner, released = self.holding("refuse:" + many(count - 1), count)
        refused = {"binding_id": many(count - 1), "code": "CAPABILITY_UNAVAILABLE", "exit_code": 4}
        first = h2.run_goal(planner, {"goal": "stop"})
        self.assertFalse(first["success"])
        self.assertIn("step limit", first["detail"])
        self.assertEqual((first["calls"], first["held"], first["refused_releases"]),
                         (h2.MAX_STEPS, [many(0), many(1), many(count - 1)], [refused]))
        self.assertEqual(first["final_state"], {"state": "releasing", "binding_id": many(1)})
        # The next stop goes on from there: the refused binding stays set aside and held,
        # and the stop fails naming it though this part of it was refused nothing.
        second = h2.run_goal(planner, {"goal": "stop"})
        self.assertEqual(self.path(second), [("releasing", "OK", "none", "releasing"),
                                             ("releasing", "OK", "none", "failed")])
        self.assertEqual((second["success"], second["calls"], second["held"],
                          second["refused_releases"]), (False, 2, [many(count - 1)], []))
        self.assertEqual(second["final_state"], dict(refused, state="failed"))
        self.assertEqual(released(), [many(index) for index in reversed(range(count))])

    def test_a_binding_of_earlier_work_is_released_by_the_stop_too(self):
        planner = self.planner("second-binding")
        self.assertTrue(h2.run_goal(planner, self.access())["success"])
        running = h2.run_goal(planner, {"goal": "run", "profile": "covered", "work_id": "other-work",
                                        "argv": [str(self.stub)]})
        self.assertEqual(self.path(running), [("start", "launching", "none", "running")])
        self.assertEqual(running["held"], ["binding_fixture", "binding_second"])
        stopped = h2.run_goal(planner, {"goal": "stop"})
        self.assertTrue(stopped["success"], stopped)
        self.assertEqual((stopped["calls"], stopped["held"]), (2, []))

    def test_a_release_answer_about_another_binding_is_not_used(self):
        mine = "binding_fixture"
        planner = self.planner("other-binding")
        self.assertTrue(h2.run_goal(planner, self.access())["success"])
        stopped = h2.run_goal(planner, {"goal": "stop"})
        self.assertFalse(stopped["success"])
        self.assertEqual(stopped["detail"], "the answer is about another binding")
        # M07-W5-R01: the release was sent, and its answer cannot be read. It may have
        # happened: it is remembered as uncertain, with the code of what was printed.
        self.assertEqual(self.path(stopped), [("ready", h2.SILENT, "none", "failed")])
        self.assertEqual(stopped["final_state"], {"state": "failed", "code": "OUTCOME_UNKNOWN",
                                                  "binding_id": mine, "exit_code": 0})
        self.assertEqual((stopped["held"], stopped["refused_releases"], stopped["outcome_unknown"]),
                         ([mine], [], []))
        self.assertEqual(stopped["unanswered"], [
            {"binding_id": mine, "code": "OK", "exit_code": 0, "request_id": None,
             "fault": "unreadable", "detail": "the answer is about another binding"}])
        self.assertEqual(planner.uncertain, {mine: {"request_id": None}})
        # A later stop observes it and does not send it again.
        later = h2.run_goal(planner, {"goal": "stop"})
        self.assertEqual(self.calls()[1:], [["access", "release", mine], ["inspect", "bindings"]])
        self.assertEqual(self.path(later), [("inspecting_release", h2.NOT_LISTED, "none", "stopped")])

    def test_a_release_that_ran_past_its_time_limit_is_observed_before_any_other_release(self):
        # M07-W5-R01, the first probe: the release prints a complete answer, and its
        # process then stays until the harness ends it. Whatever it printed, the release
        # may have happened: it is remembered, and a later stop or the close observes it
        # before it sends anything.
        mine = "binding_fixture"
        release, inspect = ["access", "release", mine], ["inspect", "bindings"]
        wait = ["operation", "wait", "op_fixture", "--timeout-ms", "20000"]
        late = {"exit_code": None, "request_id": None, "fault": "timed_out",
                "detail": "a CLI call ran past its time limit"}
        named = {"operation_id": "op_fixture"}
        # (the stub's mode, who comes next; the first attempt; the calls that follow
        #  it, and their outcomes; whether the binding is still held)
        rows = (
            # The reviewer's probe: a complete `OUTCOME_UNKNOWN` naming its operation,
            # then the close. The operation is waited on, and nothing is sent.
            ("sleep:answered:uncertain:{}:operation:released", "close",
             dict(late, outcome="outcome_unknown", code="OUTCOME_UNKNOWN", **named),
             [wait], ["released"], False),
            # The same, and the operation says the release did not happen: one new
            # release, after the observation and only then.
            ("sleep:answered:uncertain:{}:operation:never-ran", "stop",
             dict(late, outcome="outcome_unknown", code="OUTCOME_UNKNOWN", **named),
             [wait, release], ["not_run", "released"], False),
            # It printed `OK` and never ended: that is no answered release. It names
            # no operation, so the list of bindings is read.
            ("sleep:answered:normal", "stop", dict(late, outcome="unanswered", code="OK"),
             [inspect], ["not_listed"], False),
            # It printed nothing: the list says `active`, which is no evidence that
            # the release never ran. Nothing is sent.
            ("sleep:release:uncertain:{}:bindings:active", "close",
             dict(late, outcome="unanswered", code=None), [inspect], ["still_unknown"], True),
        )
        for mode, by, first, calls, outcomes, held in rows:
            with self.subTest(mode=mode, by=by):
                self.fresh()
                planner = self.planner(mode.format(mine))
                self.assertTrue(h2.run_goal(planner, self.access())["success"])
                with patch.object(h2, "CALL_SECONDS", 2.0):
                    stopped = h2.run_goal(planner, {"goal": "stop"})
                self.assertEqual(self.calls()[1:], [release])
                # The stop failed, and the attempt is recorded with what was printed.
                self.assertEqual((stopped["success"], stopped["held"], stopped["detail"]),
                                 (False, [mine], late["detail"]))
                self.assertEqual(stopped[first["outcome"]], [
                    {key: value for key, value in dict(first, binding_id=mine).items()
                     if key != "outcome"}])
                operation = {key: first[key] for key in named if key in first}
                self.assertEqual(stopped["final_state"], dict(
                    {"state": "failed", "code": "OUTCOME_UNKNOWN", "binding_id": mine}, **operation))
                self.assertEqual(planner.uncertain, {mine: dict({"request_id": None}, **operation)})
                if by == "close":
                    self.assertEqual(planner.close(), {"released": [] if held else [mine],
                                                       "held": [mine] if held else []})
                else:
                    later = h2.run_goal(planner, {"goal": "stop"})
                    self.assertEqual((later["success"], later["held"]), (not held, [mine] * held))
                # No second release without an observation between.
                self.assertEqual(self.calls()[2:], calls)
                attempts = planner.by_binding()[mine]["attempts"]
                self.assertEqual(attempts[0], dict(first, by="stop"))
                self.assertEqual([(attempt["by"], attempt["outcome"]) for attempt in attempts[1:]],
                                 [(by, outcome) for outcome in outcomes])
                self.assertEqual(planner.by_binding()[mine]["held"], held)

    def test_no_answer_about_one_binding_never_keeps_the_others_from_being_asked_about(self):
        # M07-W5-R01, the second probe: three bindings held, and no call about a
        # release ever ends. Every binding is asked about once by the stop and once by
        # the close. Each release is sent once, and stays held and reported.
        many = "binding_many_{}".format
        release = lambda index: ["access", "release", many(index)]
        late = {"exit_code": None, "request_id": None, "fault": "timed_out",
                "detail": "a CLI call ran past its time limit"}
        seen = self.watched(0.3)  # before the planner: its own closing is hurried too
        planner, _ = self.holding("sleep:always:normal", 3)
        del seen[:3]  # the three requests for access
        stopped = h2.run_goal(planner, {"goal": "stop"})
        self.assertEqual(seen, [release(2), release(1), release(0)])
        self.assertEqual(self.path(stopped), [("ready", h2.SILENT, "none", "releasing"),
                                              ("releasing", h2.SILENT, "none", "releasing"),
                                              ("releasing", h2.SILENT, "none", "failed")])
        self.assertTrue(all(step["by_table"] for step in stopped["transitions"]))
        self.assertEqual(stopped["unanswered"], [dict(late, binding_id=many(index), code=None)
                                                 for index in (2, 1, 0)])
        self.assertEqual(stopped["final_state"], {"state": "failed", "code": "OUTCOME_UNKNOWN",
                                                  "binding_id": many(2)})
        self.assertEqual((stopped["success"], stopped["calls"], stopped["detail"], stopped["held"]),
                         (False, 3, late["detail"], [many(0), many(1), many(2)]))
        self.assertEqual(planner.uncertain, {many(index): {"request_id": None} for index in (2, 1, 0)})
        # The close observes each one, and sends nothing. Its observations get no
        # answer either: each binding is still asked about, and all stay held.
        self.assertEqual(planner.close(), {"released": [], "held": [many(0), many(1), many(2)]})
        self.assertEqual(seen[3:], [["inspect", "bindings"]] * 3)
        self.assertEqual(planner.by_binding(), {many(index): {"held": True, "attempts": [
            dict(late, by="stop", outcome="unanswered", code=None),
            dict(late, by="close", outcome="still_unknown", code=None, observed="bindings")]}
            for index in (2, 1, 0)})
        self.assertEqual(sum(command[:2] == ["access", "release"] for command in seen), 3)

    def test_a_cli_that_cannot_be_started_sends_nothing_and_every_binding_is_still_tried(self):
        # A known failure before the call: nothing was sent, so nothing is uncertain.
        # Each binding has its own bounded attempt, in the stop and in the close.
        many = "binding_many_{}".format
        planner, released = self.holding("normal", 3)
        command, planner.command = planner.command, [str(self.root / "no-such-heimdall")]
        unsent = {"code": None, "exit_code": None, "fault": "not_started",
                  "detail": "the CLI could not be started"}
        stopped = h2.run_goal(planner, {"goal": "stop"})
        self.assertEqual(self.path(stopped), [("ready", h2.UNSENT, "none", "releasing"),
                                              ("releasing", h2.UNSENT, "none", "releasing"),
                                              ("releasing", h2.UNSENT, "none", "failed")])
        self.assertEqual(stopped["not_sent"], [dict(unsent, binding_id=many(index)) for index in (2, 1, 0)])
        self.assertEqual(stopped["final_state"], {"state": "failed", "code": "not_started",
                                                  "binding_id": many(2)})
        self.assertEqual((stopped["success"], stopped["detail"], stopped["unanswered"]),
                         (False, unsent["detail"], []))
        self.assertEqual(planner.close(), {"released": [], "held": [many(0), many(1), many(2)]})
        self.assertEqual(planner.by_binding(), {many(index): {"held": True, "attempts": [
            dict(unsent, by=by, outcome="not_sent") for by in ("stop", "close")]} for index in (2, 1, 0)})
        self.assertEqual((planner.uncertain, released()), ({}, []))
        # Once the CLI can be started, a stop sends each release: none was sent before.
        planner.command = command
        self.assertTrue(h2.run_goal(planner, {"goal": "stop"})["success"])
        self.assertEqual(released(), [many(2), many(1), many(0)])

    def launched(self):
        """Every process the harness starts for a launch from here on."""
        started, popen = [], subprocess.Popen

        def starting(argv, **options):
            process = popen(argv, **options)
            if argv[argv.index("--non-interactive") + 1] == "run":
                started.append(process)
            return process
        patched = patch.object(h2.subprocess, "Popen", starting)
        patched.start()
        self.addCleanup(patched.stop)
        return started

    def test_a_request_that_ran_past_its_time_limit_is_remembered_and_observed_later(self):
        # M07 W6b, the request side of M07-W5-R01: `access ensure` prints a complete
        # answer, and its process then stays until the harness ends it. The request may
        # have made a binding: what it printed is kept, it is never sent again, and a
        # later stop or the close observes what became of it.
        mine, limit = "binding_fixture", "a CLI call ran past its time limit"
        wait = ["operation", "wait", "op_fixture", "--timeout-ms", "20000"]
        release = ["access", "release", mine]
        asked = {"call": "access ensure", "profile": "late", "work_id": "work-1"}
        named = {"operation_id": "op_fixture"}
        late = dict(named, exit_code=None, fault="timed_out", detail=limit)
        seen = dict(named, observed="operation")
        # (what the operation then says, the goal's fields, who comes next; the code
        #  that was printed, and the bindings it named; the calls that follow, and the
        #  attempts they are; whether the request is still uncertain)
        rows = (
            # It printed `ACCESS_READY` with a binding: that is not the goal met, and the
            # binding is held all the same. Nothing is left to observe: the close
            # releases it.
            ("normal", {}, "close", "ACCESS_READY", [mine], [release], [], False),
            # It named an operation. Observed: the operation succeeded and names the
            # binding it made, which the close then releases.
            ("normal", {"timeout_ms": 1}, "close", "ACCEPTED", [], [wait, release],
             [dict(seen, outcome="binding_found", code="ACCESS_READY", exit_code=0, bindings=[mine])],
             False),
            ("normal", {"timeout_ms": 1}, "stop", "ACCEPTED", [], [wait, release],
             [dict(seen, outcome="binding_found", code="ACCESS_READY", exit_code=0, bindings=[mine])],
             False),
            # Observed: the operation failed with effect `none`. Nothing to release.
            ("denied", {"timeout_ms": 1}, "close", "ACCEPTED", [], [wait],
             [dict(seen, outcome="not_run", code="CAPABILITY_UNAVAILABLE", exit_code=4)], False),
            ("denied", {"timeout_ms": 1}, "stop", "ACCEPTED", [], [wait],
             [dict(seen, outcome="not_run", code="CAPABILITY_UNAVAILABLE", exit_code=4)], False),
            # Observed: the operation is still unfinished. Still unknown, and named.
            ("never", {"timeout_ms": 1}, "close", "ACCEPTED", [], [wait],
             [dict(seen, outcome="still_unknown", code="OK", exit_code=5)], True),
            ("never", {"timeout_ms": 1}, "stop", "ACCEPTED", [], [wait],
             [dict(seen, outcome="still_unknown", code="OK", exit_code=5)], True),
        )
        for mode, fields, by, code, bindings, calls, later, uncertain in rows:
            with self.subTest(mode=mode, fields=fields, by=by):
                self.fresh()
                planner = self.planner(mode)
                with patch.object(h2, "CALL_SECONDS", 2.0):
                    record = h2.run_goal(planner, self.access("late", **fields))
                request_id = self.calls()[0][7]
                first = dict(asked, request_id=request_id, code=code, **late)
                if bindings:
                    first["bindings"] = bindings
                # The goal failed where it stood: a printed `ACCESS_READY` from a process
                # that never ended is not `ready`. The attempt is recorded with what
                # was printed, and `failed` names the request.
                self.assertEqual((record["success"], record["detail"], record["held"]),
                                 (False, limit, bindings))
                self.assertEqual(self.path(record), [("start", h2.UNANSWERED, "none", "failed")])
                self.assertTrue(record["transitions"][0]["by_table"])
                self.assertEqual(record["final_state"], dict(
                    named, state="failed", code="OUTCOME_UNKNOWN", request_id=request_id))
                self.assertEqual(record["requests_unanswered"], [first])
                self.assertEqual((record["requests_not_sent"], record["requests_still_unknown"],
                                  record["unanswered"]), ([], [], []))
                # A request that named its binding has nothing left to observe.
                self.assertEqual(planner.requests,
                                 {} if bindings else {request_id: dict(asked, **named)})
                if by == "close":
                    self.assertEqual(planner.close(), {"released": [mine] * (release in calls),
                                                       "held": []})
                else:
                    stopped = h2.run_goal(planner, {"goal": "stop"})
                    outcome = later[0]["outcome"]
                    path = {"binding_found": [("observing_request", h2.FOUND, "none", "releasing"),
                                              ("releasing", "OK", "none", "stopped")],
                            "not_run": [("observing_request", h2.NEVER_RAN, "none", "stopped")],
                            "still_unknown": [("observing_request", h2.STILL_OPEN, "none", "failed")]}
                    self.assertEqual(self.path(stopped), path[outcome])
                    self.assertTrue(all(step["by_table"] for step in stopped["transitions"]))
                    self.assertEqual((stopped["success"], stopped["calls"], stopped["held"]),
                                     (not uncertain, len(calls), []))
                    # A request the stop could not settle is in its record, and `failed`
                    # names it.
                    self.assertEqual(stopped["requests_still_unknown"], [
                        {key: value for key, value in dict(asked, request_id=request_id,
                                                           **later[0]).items() if key != "outcome"}
                    ] * uncertain)
                    if uncertain:
                        self.assertEqual(stopped["final_state"], dict(
                            named, state="failed", code="OUTCOME_UNKNOWN", request_id=request_id))
                        self.assertEqual(stopped["detail"], "failed: OUTCOME_UNKNOWN")
                # The observation comes first, and the request is never sent again.
                self.assertEqual(self.calls()[1:], calls)
                self.assertEqual(sum(call[:2] == ["access", "ensure"] for call in self.calls()), 1)
                self.assertEqual((planner.held, set(planner.requests)),
                                 ([], {request_id} if uncertain else set()))
                # The request's attempts, in order.
                own = {key: value for key, value in first.items() if key not in (*asked, "request_id")}
                self.assertEqual(planner.by_request(), {request_id: dict(
                    asked, uncertain=uncertain, attempts=[
                        dict(own, by="access", outcome="unanswered"),
                        *(dict(attempt, by=by) for attempt in later)])})
                self.assertEqual(planner.by_binding(), {})

    def test_a_request_with_no_usable_output_is_observed_by_the_list_of_bindings_for_its_work(self):
        # It named no operation, and today's CLI has no way to observe a request by its
        # ID. The typed means left is the complete list of this caller's bindings, read
        # for the work of the request.
        found, other = "binding_second", "binding_many_7"
        inspect = ["inspect", "bindings"]
        release = lambda binding: ["access", "release", binding]
        asked = lambda profile: {"call": "access ensure", "profile": profile, "work_id": "work-1"}
        late = {"code": None, "exit_code": None, "fault": "timed_out",
                "detail": "a CLI call ran past its time limit"}
        garbled = {"code": None, "exit_code": 0, "fault": "unreadable",
                   "detail": "the CLI printed something that is not JSON"}
        ok = {"code": "OK", "exit_code": 0, "observed": "bindings"}
        defect = "exit 4 does not fit OK: its documented exit class is 0; a probable product defect"
        # (the profile, what the list says of the work, who comes next; the request's
        #  own attempt; the observation; the releases that follow)
        rows = (
            # The list names a binding for that work, `active`, that H2 does not hold:
            # it is a binding to release, and it is released.
            ("silent", f"{found}:active", "close", late,
             dict(ok, outcome="binding_found", listed=[found], bindings=[found]), [found]),
            ("silent", f"{found}:active", "stop", late,
             dict(ok, outcome="binding_found", listed=[found], bindings=[found]), [found]),
            ("silent", f"{found},{other}:active", "close", late,
             dict(ok, outcome="binding_found", listed=[found, other], bindings=[found, other]),
             [other, found]),
            # The answer could not be read: the same, with the exit status it had.
            ("garbled", f"{found}:active", "close", garbled,
             dict(ok, outcome="binding_found", listed=[found], bindings=[found]), [found]),
            # The list names no binding for that work, or none that is `active`: that is
            # no evidence that the request never ran. Still unknown, and nothing is sent.
            ("silent", f"{found}:none", "close", late, dict(ok, outcome="still_unknown", listed=[]), []),
            ("silent", f"{found}:none", "stop", late, dict(ok, outcome="still_unknown", listed=[]), []),
            ("silent", f"{found}:released", "close", late,
             dict(ok, outcome="still_unknown", listed=[]), []),
            ("silent", f"{found}:odd", "close", late, dict(ok, outcome="still_unknown", listed=[]), []),
            # The list could not be read, or came in the wrong exit class: still unknown.
            ("silent", f"{found}:unknown", "close", late,
             {"outcome": "still_unknown", "code": "SERVICE_UNAVAILABLE", "exit_code": 5,
              "observed": "bindings"}, []),
            ("silent", f"{found}:wrong-exit", "close", late,
             dict(ok, outcome="still_unknown", exit_code=4, listed=[found], inconsistent=True,
                  detail=defect), []),
        )
        seen = self.watched(0.5, limited=(["access", "ensure"],))
        for profile, says, by, own, observation, released in rows:
            with self.subTest(profile=profile, says=says, by=by):
                del seen[:]
                planner = self.planner(f"work:{says}")
                record = h2.run_goal(planner, self.access(profile))
                request_id = seen[0][7]
                uncertain = observation["outcome"] == "still_unknown"
                self.assertEqual((record["success"], record["detail"], record["held"]),
                                 (False, own["detail"], []))
                self.assertEqual(self.path(record), [("start", h2.UNANSWERED, "none", "failed")])
                self.assertEqual(record["final_state"], {"state": "failed", "code": "OUTCOME_UNKNOWN",
                                                         "request_id": request_id})
                self.assertEqual(record["requests_unanswered"],
                                 [dict(asked(profile), request_id=request_id, **own)])
                self.assertEqual(planner.requests, {request_id: asked(profile)})
                if by == "close":
                    # What the close released, in the order the bindings were held.
                    self.assertEqual(planner.close(), {"released": released[::-1], "held": []})
                else:
                    stopped = h2.run_goal(planner, {"goal": "stop"})
                    self.assertEqual(self.path(stopped), [
                        ("inspecting_request", h2.STILL_OPEN, "none", "failed")] if uncertain else [
                        ("inspecting_request", h2.FOUND, "none", "releasing"),
                        ("releasing", "OK", "none", "stopped")])
                    self.assertTrue(all(step["by_table"] for step in stopped["transitions"]))
                    self.assertEqual((stopped["success"], stopped["held"]), (not uncertain, []))
                    if uncertain:
                        self.assertEqual(stopped["final_state"], {
                            "state": "failed", "code": "OUTCOME_UNKNOWN", "request_id": request_id})
                        self.assertEqual(stopped["requests_still_unknown"], [
                            {key: value for key, value in dict(
                                asked(profile), request_id=request_id, **observation).items()
                             if key != "outcome"}])
                # One request, one reading of the list, and a release of each binding
                # the list showed, the newest first. The request is never sent again.
                self.assertEqual(seen[1:], [inspect, *map(release, released)])
                self.assertEqual(sum(command[:2] == ["access", "ensure"] for command in seen), 1)
                self.assertEqual((planner.held, set(planner.requests)),
                                 ([], {request_id} if uncertain else set()))
                self.assertEqual(planner.by_request(), {request_id: dict(
                    asked(profile), uncertain=uncertain, attempts=[
                        dict(own, by="access", outcome="unanswered"), dict(observation, by=by)])})

    def test_a_binding_already_held_for_the_work_is_no_evidence_of_the_request(self):
        # The list names one binding for the work, and H2 held it before the request
        # was sent: that is what the list would say had the request never run. The
        # binding is released like any other, and the request stays unknown.
        mine = "binding_fixture"
        seen = self.watched(0.5, limited=(["access", "ensure"],))
        planner = self.planner(f"work:{mine}:active")
        self.assertTrue(h2.run_goal(planner, self.access())["success"])
        record = h2.run_goal(planner, self.access("silent"))
        self.assertEqual((record["success"], record["held"]), (False, [mine]))
        request_id = seen[1][7]
        self.assertEqual(planner.close(), {"released": [mine], "held": []})
        self.assertEqual(seen[2:], [["inspect", "bindings"], ["access", "release", mine]])
        entry = planner.by_request()[request_id]
        self.assertEqual((entry["uncertain"], entry["attempts"][1:]), (True, [
            {"by": "close", "outcome": "still_unknown", "code": "OK", "exit_code": 0,
             "observed": "bindings", "listed": [mine]}]))
        self.assertEqual(set(planner.requests), {request_id})

    def test_a_request_with_no_answer_is_never_sent_again(self):
        # Two stops, a new request for the same work, its stop, and the close: the
        # request that brought no answer is sent once. Each stop and the close observe
        # it once, and it stays uncertain and reported.
        ensure, inspect = ["access", "ensure"], ["inspect", "bindings"]
        seen = self.watched(0.5, limited=(ensure,))
        planner = self.planner("work:binding_second:none")
        self.assertFalse(h2.run_goal(planner, self.access("silent"))["success"])
        request_id = seen[0][7]
        stops = [h2.run_goal(planner, {"goal": "stop"}) for _ in range(2)]
        again = h2.run_goal(planner, self.access())
        self.assertTrue(again["success"], again)
        last = h2.run_goal(planner, {"goal": "stop"})
        self.assertEqual(planner.close(), {"released": [], "held": []})
        self.assertEqual([command[:2] for command in seen],
                         [ensure, inspect, inspect, ensure, inspect, ["access", "release"], inspect])
        # The later request is one of its own: every request has its own ID.
        sent = [command[7] for command in seen if command[:2] == ensure]
        self.assertEqual((sent.count(request_id), len(set(sent))), (1, 2))
        self.assertEqual([(stop["success"], stop["held"]) for stop in stops + [last]],
                         [(False, [])] * 3)
        # The last stop released the binding of the later request, and still failed.
        self.assertEqual(self.path(last), [("inspecting_request", h2.STILL_OPEN, "none", "releasing"),
                                           ("releasing", "OK", "none", "failed")])
        self.assertEqual(last["final_state"], {"state": "failed", "code": "OUTCOME_UNKNOWN",
                                               "request_id": request_id})
        self.assertEqual([(attempt["by"], attempt["outcome"])
                          for attempt in planner.by_request()[request_id]["attempts"]],
                         [("access", "unanswered")] + [("stop", "still_unknown")] * 3
                         + [("close", "still_unknown")])
        self.assertEqual(list(planner.by_request()), [request_id])

    def test_a_request_that_was_never_started_is_not_sent_and_is_not_uncertain(self):
        # A known failure before the call: nothing was sent, so nothing is remembered
        # and nothing is observed.
        planner = self.planner()
        command, planner.command = planner.command, [str(self.root / "no-such-heimdall")]
        unsent = {"code": None, "exit_code": None, "fault": "not_started",
                  "detail": "the CLI could not be started"}
        launch = {"goal": "run", "profile": "covered", "work_id": "work-1", "argv": [str(self.stub)]}
        for goal, call in ((self.access(), "access ensure"), (launch, "run")):
            with self.subTest(call=call):
                record = h2.run_goal(planner, goal)
                self.assertEqual((record["success"], record["detail"]), (False, unsent["detail"]))
                self.assertEqual(self.path(record), [("start", h2.NOT_STARTED, "none", "failed")])
                self.assertTrue(record["transitions"][0]["by_table"])
                [entry] = record["requests_not_sent"]
                self.assertEqual(entry, dict(unsent, call=call, profile="covered", work_id="work-1",
                                             request_id=entry["request_id"]))
                self.assertEqual(record["final_state"], {"state": "failed", "code": "not_started",
                                                         "request_id": entry["request_id"]})
                self.assertEqual((record["requests_unanswered"], record["requests_still_unknown"]),
                                 ([], []))
        self.assertEqual((planner.requests, planner.held, planner.child, self.calls()),
                         ({}, [], None, []))
        self.assertEqual(planner.close(), {"released": [], "held": []})
        self.assertEqual([(entry["call"], entry["uncertain"], len(entry["attempts"]))
                          for entry in planner.by_request().values()],
                         [("access ensure", False, 1), ("run", False, 1)])
        self.assertEqual(self.calls(), [])
        # A launch environment that fails its check sends nothing either.
        homeless = {key: value for key, value in self.environment.items() if key != "HOME"}
        record = h2.run_goal(self.planner(environment=homeless), self.access())
        self.assertEqual([(entry["fault"], entry["detail"]) for entry in record["requests_not_sent"]],
                         [("not_started", "HOME is not set to an existing absolute directory")])
        self.assertEqual((record["calls"], self.calls()), (0, []))
        # Once the CLI can be started, a goal is a new request, and it is sent.
        planner.command = command
        self.assertTrue(h2.run_goal(planner, self.access())["success"])
        self.assertEqual(len(self.calls()), 1)

    def test_a_launch_that_brought_no_answer_is_remembered_with_what_its_record_named(self):
        mine, found = "binding_fixture", "binding_second"
        limit = "a CLI call ran past its time limit"
        goal = lambda profile="covered": {"goal": "run", "profile": profile, "work_id": "work-1",
                                          "argv": [str(self.stub)]}
        asked = lambda profile="covered": {"call": "run", "profile": profile, "work_id": "work-1"}
        started, seen = self.launched(), self.watched()
        # Its run record was written before the time limit: the binding and the
        # operation it names are kept. The binding is held, and the close releases it.
        planner = self.planner("sleep:run-recorded:normal")
        with patch.object(h2, "LAUNCH_SECONDS", 2.0):
            record = h2.run_goal(planner, goal())
        [process] = started
        [first] = record["requests_unanswered"]
        request_id = first["request_id"]
        self.assertEqual(first, dict(asked(), request_id=request_id, code=None, exit_code=None,
                                     fault="timed_out", detail=limit, operation_id="op_fixture",
                                     bindings=[mine]))
        self.assertEqual((record["success"], record["detail"], record["held"], record["calls"]),
                         (False, limit, [mine], 1))
        self.assertEqual(self.path(record), [("start", h2.UNANSWERED, "none", "failed")])
        self.assertEqual(record["final_state"], {"state": "failed", "code": "OUTCOME_UNKNOWN",
                                                 "request_id": request_id, "operation_id": "op_fixture"})
        # H2 holds no child from a launch that timed out: it ended that process through
        # its own handle at the time limit, so the close has none to end.
        self.assertEqual((planner.child, process.poll() is not None), (None, True))
        self.assertEqual((planner.requests, list(self.root.glob("h2-run-*"))), ({}, []))
        self.assertEqual(planner.close(), {"released": [mine], "held": []})
        self.assertEqual(seen, [["access", "release", mine]])
        self.assertEqual(planner.by_request()[request_id]["uncertain"], False)
        # (the stub's mode, the profile, the launch's time limit; the request's own
        #  attempt; the observation by the close; what the close released)
        late = {"code": None, "exit_code": None, "fault": "timed_out", "detail": limit}
        garbled = {"code": None, "exit_code": 1, "fault": "unreadable",
                   "detail": "the CLI printed something that is not JSON"}
        ok = {"by": "close", "code": "OK", "exit_code": 0, "observed": "bindings"}
        rows = (
            # No record and no line before the time limit: the request is observed by
            # the list of bindings for its work, and the binding it shows is released.
            (f"sleep:run:work:{found}:active", "covered", 0.5, late,
             dict(ok, outcome="binding_found", listed=[found], bindings=[found]), [found]),
            (f"sleep:run:work:{found}:none", "covered", 0.5, late,
             dict(ok, outcome="still_unknown", listed=[]), []),
            # It ended by itself, and what it left is neither a run record nor one
            # envelope: uncertain in the same way.
            (f"work:{found}:none", "garbled", h2.LAUNCH_SECONDS, garbled,
             dict(ok, outcome="still_unknown", listed=[]), []),
        )
        for mode, profile, seconds, own, observation, released in rows:
            with self.subTest(mode=mode, profile=profile):
                del started[:], seen[:]
                planner = self.planner(mode)
                with patch.object(h2, "LAUNCH_SECONDS", seconds):
                    record = h2.run_goal(planner, goal(profile))
                [process] = started
                [first] = record["requests_unanswered"]
                request_id = first["request_id"]
                self.assertEqual(first, dict(asked(profile), request_id=request_id, **own))
                self.assertEqual((record["success"], record["detail"], record["held"]),
                                 (False, own["detail"], []))
                self.assertEqual(record["final_state"], {"state": "failed", "code": "OUTCOME_UNKNOWN",
                                                         "request_id": request_id})
                self.assertEqual((planner.child, process.poll() is not None), (None, True))
                self.assertEqual(planner.requests, {request_id: asked(profile)})
                self.assertEqual(planner.close(), {"released": released, "held": []})
                # The launch is never started again: the close observes, then releases.
                self.assertEqual((len(started), seen),
                                 (1, [["inspect", "bindings"],
                                      *(["access", "release", binding] for binding in released)]))
                self.assertEqual(planner.by_request(), {request_id: dict(
                    asked(profile), uncertain=not released, attempts=[
                        dict(own, by="run", outcome="unanswered"), observation])})

    def test_run_from_the_start_and_stop_from_ready(self):
        planner = self.planner()
        goal = {"goal": "run", "profile": "covered", "work_id": "work-2",
                "argv": [str(self.stub)]}
        running = h2.run_goal(planner, goal)
        self.assertEqual(self.path(running), [("start", "launching", "none", "running")])
        # A new goal is refused while the child runs; stop ends it.
        refused = h2.run_goal(planner, self.access())
        self.assertFalse(refused["success"])
        self.assertEqual(refused["calls"], 0)
        self.assertTrue(h2.run_goal(planner, {"goal": "stop"})["success"])
        self.assertFalse(h2.run_goal(planner, {"goal": "stop"})["success"])  # nothing held now
        self.assertTrue(h2.run_goal(planner, self.access())["success"])
        released = h2.run_goal(planner, {"goal": "stop"})
        self.assertEqual(self.path(released), [("ready", "OK", "none", "stopped")])
        self.assertNotIn("child_exit_code", released)

    def test_a_refused_launch_is_read_from_its_envelope(self):
        planner = self.planner("refused-launch")
        record = h2.run_goal(planner, {"goal": "run", "profile": "covered", "work_id": "work-3",
                                       "argv": [str(self.stub)]})
        self.assertFalse(record["success"])
        self.assertEqual(record["final_state"], {"state": "failed", "code": "CAPABILITY_UNAVAILABLE"})
        self.assertIsNone(planner.child)

    def test_a_launch_that_cannot_be_trusted_ends_the_child(self):
        for mode, expected in (("silent-child", "wrote no line"), ("other-pid", "another process")):
            with self.subTest(mode=mode):
                planner = self.planner(mode)
                record = h2.run_goal(planner, {"goal": "run", "profile": "covered",
                                               "work_id": "work-4", "argv": [str(self.stub)]})
                self.assertFalse(record["success"])
                self.assertIn(expected, record["detail"])
                self.assertIsNone(planner.child)
                self.assertEqual(list(self.root.glob("h2-run-*")), [])
                # The binding its run record named is held all the same, and a stop releases it.
                self.assertEqual(record["held"], ["binding_fixture"])
                seen = len(self.calls())
                stopped = h2.run_goal(planner, {"goal": "stop"})
                self.assertEqual((stopped["success"], stopped["held"]), (True, []), stopped)
                self.assertEqual(self.calls()[seen:], [["access", "release", "binding_fixture"]])

    def test_a_child_outside_the_scratch_root_is_never_started(self):
        record = h2.run_goal(self.planner(), {"goal": "run", "profile": "covered",
                                              "work_id": "work-5", "argv": [sys.executable]})
        self.assertFalse(record["success"])
        self.assertEqual((record["calls"], self.calls()), (0, []))

    def test_a_child_that_ignores_its_input_is_stopped_by_handle(self):
        planner = self.planner("stubborn-child")
        goal = {"goal": "run", "profile": "covered", "work_id": "work-6", "argv": [str(self.stub)]}
        self.assertTrue(h2.run_goal(planner, goal)["success"])
        process = planner.child.process
        with patch.object(h2, "CHILD_END_SECONDS", 0.5):
            stopped = h2.run_goal(planner, {"goal": "stop"})
        self.assertFalse(stopped["success"])
        self.assertIsNotNone(process.returncode)
        self.assertNotEqual(stopped["child_exit_code"], 0)
        self.assertEqual(stopped["final_state"], {"state": "stopped"})

    def test_close_ends_a_child_that_was_never_stopped(self):
        planner = self.planner()
        goal = {"goal": "run", "profile": "covered", "work_id": "work-7", "argv": [str(self.stub)]}
        self.assertTrue(h2.run_goal(planner, goal)["success"])
        process = planner.child.process
        planner.close()
        self.assertIsNotNone(process.returncode)

    def test_a_missing_or_foreign_home_prevents_every_launch(self):
        elsewhere = tempfile.TemporaryDirectory(prefix="heimdall-h2-other-",
                                                dir="/tmp" if os.name == "posix" else None)
        self.addCleanup(elsewhere.cleanup)
        (self.root / "acct" / "nested").mkdir()
        cases = {
            "missing": {key: value for key, value in self.environment.items() if key != "HOME"},
            "relative": dict(self.environment, HEIMDALL_HOME="hm"),
            "foreign": dict(self.environment, HEIMDALL_TEST_SSH_HOME=elsewhere.name),
            "shared": dict(self.environment, HEIMDALL_HOME=self.environment["HOME"]),
            "nested": dict(self.environment, HEIMDALL_HOME=str(self.root / "acct" / "nested")),
            "root": dict(self.environment, HOME=str(self.root)),
            "missing management store": {key: value for key, value in self.environment.items()
                                         if key != "HEIMDALL_TEST_MGMT_STORE"},
            "missing transport store": {key: value for key, value in self.environment.items()
                                        if key != "HEIMDALL_TEST_IROH_KEY_STORE"},
            "bare management path": dict(self.environment,
                                         HEIMDALL_TEST_MGMT_STORE=str(self.root / "mgmt-store")),
            "relative management store": dict(self.environment,
                                              HEIMDALL_TEST_MGMT_STORE="fixture-file:mgmt-store"),
            "relative transport store": dict(self.environment, HEIMDALL_TEST_IROH_KEY_STORE="iroh"),
            "foreign management store": dict(self.environment,
                                             HEIMDALL_TEST_MGMT_STORE=f"fixture-file:{elsewhere.name}/mgmt"),
            "foreign transport store": dict(self.environment,
                                            HEIMDALL_TEST_IROH_KEY_STORE=f"{elsewhere.name}/iroh"),
        }
        for name, environment in cases.items():
            with self.subTest(case=name):
                record = h2.run_goal(self.planner(environment=environment), {"goal": "discover"})
                self.assertFalse(record["success"])
                self.assertEqual(record["calls"], 0)
                self.assertEqual(self.calls(), [])

    @unittest.skipUnless(os.name == "posix", "requires fixture symlinks")
    def test_a_redirected_home_prevents_every_launch_and_spelling_is_kept(self):
        link = self.root / "link"
        link.symlink_to(Path(tempfile.gettempdir()), target_is_directory=True)
        record = h2.run_goal(self.planner(environment=dict(self.environment, HOME=str(link))),
                             {"goal": "discover"})
        self.assertFalse(record["success"])
        self.assertEqual(self.calls(), [])
        for key, prefix in h2.STORES.items():
            with self.subTest(store=key):
                record = h2.run_goal(self.planner(environment=dict(self.environment, **{
                    key: f"{prefix}{link / 'missing'}",
                })), {"goal": "discover"})
                self.assertFalse(record["success"])
                self.assertEqual(record["calls"], 0)
                self.assertEqual(self.calls(), [])
        # A home reached through a link that stays inside the root is passed as it was given.
        inside = self.root / "alias"
        inside.symlink_to(self.root / "hm", target_is_directory=True)
        env = h2.launch_environment(self.root, dict(self.environment, HEIMDALL_HOME=str(inside)))
        self.assertEqual(env["HEIMDALL_HOME"], str(inside))
        self.assertEqual(sorted(env), ["HEIMDALL_HOME", "HEIMDALL_TEST_IROH_KEY_STORE",
                                       "HEIMDALL_TEST_MGMT_STORE", "HEIMDALL_TEST_SECRET_STORE",
                                       "HEIMDALL_TEST_SSH_HOME", "HOME", "LANG", "PATH", "TERM"])

    def test_windows_variables_are_found_under_any_spelling_of_their_names(self):
        # On Windows `os.environ` holds its names upper-cased, so the copy H2 is given has
        # `SYSTEMROOT` and no `SystemRoot` (the native run of 2026-11-22: every task ended
        # "SystemRoot is not an absolute Windows directory" with no call made).
        given = {key.upper(): value for key, value in self.environment.items()}
        given["SYSTEMROOT"] = r"C:\Windows"
        self.assertNotIn("SystemRoot", given)
        env = h2.launch_environment(self.root, given, windows=True)
        self.assertEqual(env["SystemRoot"], r"C:\Windows")
        self.assertEqual(env["PATH"],
                         r"C:\Windows\System32\OpenSSH;C:\Windows\System32;C:\Windows")
        for name in h2.HOMES:
            self.assertEqual(env[name], self.environment[name])
        self.assertEqual(env["USERPROFILE"], self.environment["HOME"])
        # Off Windows a name is its exact spelling: nothing is taken from another one.
        with self.assertRaises(h2.PlannerError):
            h2.launch_environment(self.root, {key.lower(): value
                                              for key, value in self.environment.items()},
                                  windows=False)

    def test_a_store_path_that_cannot_be_resolved_is_refused_as_a_planner_error(self):
        # Whether a looping link raises depends on the Python version, so the failure is
        # injected: the point is that it comes out as this harness's own error.
        with patch.object(h2.Path, "resolve", side_effect=OSError("unreadable")), \
                self.assertRaises(h2.PlannerError) as refused:
            h2.launch_environment(self.root, self.environment)
        self.assertIn("could not be resolved", str(refused.exception))

    def test_goals_are_checked_before_any_call(self):
        bad = [[], {"goal": "approve"}, {"goal": ["access"]}, {"goal": "access", "profile": "covered"},
               {"goal": "access", "profile": "--home", "work_id": "w"},
               {"goal": "access", "profile": "p", "work_id": "w", "pairs": ["h3"]},
               {"goal": "access", "profile": "p", "work_id": "w", "argv": ["/bin/sh"]},
               {"goal": "run", "profile": "p", "work_id": "w"},
               {"goal": "stop", "binding_id": "binding_x"},
               {"goal": "discover", "task": "two words"}]
        planner = self.planner()
        for goal in bad:
            with self.subTest(goal=goal):
                record = h2.run_goal(planner, goal)
                self.assertFalse(record["success"])
                self.assertEqual(record["calls"], 0)
        self.assertEqual(self.calls(), [])

    def test_terminal_handoff_reports_one_line_and_waits_for_continue(self):
        report = {"handoff": "approval", "decision_ref": "dec_fixture", "operation_id": "op_fixture"}
        for typed, expected in (("continue\n", True), ("", False), ("yes\n", False)):
            stderr = io.StringIO()
            with patch.object(sys, "stdin", io.StringIO(typed)), contextlib.redirect_stderr(stderr):
                self.assertIs(h2.terminal_handoff(report), expected)
            self.assertEqual(json.loads(stderr.getvalue()), report)
            self.assertEqual(stderr.getvalue().count("\n"), 1)

    @unittest.skipUnless(os.name == "posix", "the stub is started through its interpreter line")
    def test_main_prints_one_summary_and_reports_failure_by_exit_code(self):
        self.stub.write_text(f"#!{sys.executable} -IB\n{STUB}", encoding="utf-8")
        self.stub.chmod(0o700)
        stdout = io.StringIO()
        goals = [json.dumps({"goal": "discover"}), json.dumps(self.access()),
                 json.dumps(self.access("novel", task="novel"))]
        argv = ["--heimdall-bin", str(self.stub), "--scratch-root", str(self.root)]
        for goal in goals:
            argv += ["--goal", goal]
        with patch.dict(os.environ, self.environment), contextlib.redirect_stdout(stdout):
            status = h2.main(argv)
        self.assertEqual(status, 1)
        self.assertEqual(len(stdout.getvalue().splitlines()), 1)
        summary = json.loads(stdout.getvalue())
        self.assertEqual(summary["harness"], "H2")
        self.assertIn("held for U4b", summary["call_set"])
        self.assertEqual([task["task"] for task in summary["tasks"]], ["discover", "access", "novel"])
        self.assertEqual([task["success"] for task in summary["tasks"]], [True, True, False])
        # The binding the goals left held was released before the process ended.
        self.assertEqual(summary["close"], {"released": ["binding_fixture"], "held": []})
        self.assertEqual(self.calls()[-1], ["access", "release", "binding_fixture"])
        self.assertEqual((summary["release_attempts"], summary["request_attempts"]), ({}, {}))
        self.assertEqual(sorted(summary), ["call_set", "close", "harness", "release_attempts",
                                           "request_attempts", "tasks"])
        for task in summary["tasks"]:
            for field in ("calls", "round_trips", "human_handoffs", "invalid_retries",
                          "wall_time_ms", "discovery_bytes", "detail", "skipped", "final_state",
                          "held", "refused_releases", "outcome_unknown", "unanswered", "not_sent",
                          "still_unknown", "not_listed", "requests_unanswered",
                          "requests_not_sent", "requests_still_unknown"):
                self.assertIn(field, task)

    @unittest.skipUnless(os.name == "posix", "the stub is started through its interpreter line")
    def test_main_exits_1_when_a_release_was_refused_and_names_it(self):
        many = "binding_many_{}".format
        refused = {"binding_id": many(1), "code": "CAPABILITY_UNAVAILABLE", "exit_code": 4}
        default = 'mode = "normal" if'
        self.assertEqual(STUB.count(default), 1)
        stub = STUB.replace(default, f'mode = "refuse:{many(1)}" if')
        self.stub.write_text(f"#!{sys.executable} -IB\n{stub}", encoding="utf-8")
        self.stub.chmod(0o700)
        access = [json.dumps(self.access("many", task=f"access-{index}")) for index in range(3)]
        # The refusal meets a stop goal, or only the close that ends the run.
        for last, close in (([json.dumps({"goal": "stop"})], {"released": [], "held": [many(1)]}),
                            ([], {"released": [many(0), many(2)], "held": [many(1)]})):
            with self.subTest(stop_goal=bool(last)):
                for name in ("calls.jsonl", "count-many"):
                    (self.root / name).unlink(missing_ok=True)
                argv = ["--heimdall-bin", str(self.stub), "--scratch-root", str(self.root)]
                for goal in access + last:
                    argv += ["--goal", goal]
                stdout = io.StringIO()
                with patch.dict(os.environ, self.environment), contextlib.redirect_stdout(stdout):
                    status = h2.main(argv)
                self.assertEqual(status, 1)
                summary = json.loads(stdout.getvalue())
                self.assertEqual([task["success"] for task in summary["tasks"]],
                                 [True, True, True] + [False] * len(last))
                self.assertEqual(summary["close"], close)
                # A stop goal's refusal is in its record, and the close then asks once
                # more. The summary has one entry for the binding, with its attempts in
                # order: the stop, then the close.
                attempt = {"outcome": "refused", "code": "CAPABILITY_UNAVAILABLE", "exit_code": 4}
                self.assertEqual(summary["release_attempts"], {many(1): {"held": True, "attempts": [
                    dict(attempt, by=by) for by in ["stop"] * len(last) + ["close"]]}})
                self.assertEqual([task["refused_releases"] for task in summary["tasks"]],
                                 [[], [], []] + [[refused]] * len(last))
                self.assertEqual([call[2] for call in self.calls()[3:]],
                                 [many(2), many(1), many(0)] + [many(1)] * len(last))

    @unittest.skipUnless(os.name == "posix", "the stub is started through its interpreter line")
    def test_main_exits_1_when_no_call_about_a_release_was_answered_and_names_every_binding(self):
        # M07-W5-R01, the second probe as a whole run: a stop goal, then the close.
        many = "binding_many_{}".format
        default = 'mode = "normal" if'
        stub = STUB.replace(default, 'mode = "sleep:always:normal" if')
        self.stub.write_text(f"#!{sys.executable} -IB\n{stub}", encoding="utf-8")
        self.stub.chmod(0o700)
        argv = ["--heimdall-bin", str(self.stub), "--scratch-root", str(self.root)]
        for goal in [self.access("many", task=f"access-{index}") for index in range(3)] + [{"goal": "stop"}]:
            argv += ["--goal", json.dumps(goal)]
        seen, stdout = self.watched(0.3), io.StringIO()
        with patch.dict(os.environ, self.environment), contextlib.redirect_stdout(stdout):
            status = h2.main(argv)
        self.assertEqual(status, 1)
        summary = json.loads(stdout.getvalue())
        self.assertEqual([task["success"] for task in summary["tasks"]], [True, True, True, False])
        self.assertEqual(summary["close"], {"released": [], "held": [many(0), many(1), many(2)]})
        # Each binding was asked about by the stop (its release, sent once) and by the
        # close (an observation), and each is reported with both attempts.
        self.assertEqual([command[:3] for command in seen[3:]],
                         [["access", "release", many(index)] for index in (2, 1, 0)]
                         + [["inspect", "bindings"]] * 3)
        self.assertEqual({binding: [(attempt["by"], attempt["outcome"], attempt["fault"])
                                    for attempt in entry["attempts"]]
                          for binding, entry in summary["release_attempts"].items()},
                         {many(index): [("stop", "unanswered", "timed_out"),
                                        ("close", "still_unknown", "timed_out")] for index in (2, 1, 0)})
        self.assertTrue(all(entry["held"] for entry in summary["release_attempts"].values()))

    @unittest.skipUnless(os.name == "posix", "the stub is started through its interpreter line")
    def test_main_exits_1_after_an_uncertain_release_and_lists_its_attempts_by_binding(self):
        many = "binding_many_{}".format
        default = 'mode = "normal" if'
        access = [json.dumps(self.access("many", task=f"access-{index}")) for index in range(3)]
        stop = [json.dumps({"goal": "stop"})]
        unknown = {"outcome": "outcome_unknown", "code": "OUTCOME_UNKNOWN", "exit_code": 7,
                   "request_id": None}
        operation = {"operation_id": "op_fixture"}
        still = {"outcome": "still_unknown", "request_id": None}
        # (how the uncertain answer named its operation, what the observation says,
        #  whether a stop goal comes before the close; what the close reports released;
        #  the binding's attempts after the first, each made by the close; whether it is
        #  still held)
        rows = (
            # the operation is observed released
            ("operation", "released", True, [many(1)],
             [{"outcome": "released", "code": "OK", "exit_code": 0, "observed": "operation"}], False),
            # the operation says the release did not happen: one new release
            ("operation", "never-ran", True, [many(1)],
             [{"outcome": "not_run", "code": "CAPABILITY_UNAVAILABLE", "exit_code": 4,
               "observed": "operation"}, {"outcome": "released", "code": "OK", "exit_code": 0}], False),
            # the operation is still unfinished, or its own outcome is unknown
            ("operation", "unfinished", True, [],
             [dict(still, code="OK", exit_code=5, observed="operation", **operation)], True),
            ("operation", "unknown", True, [],
             [dict(still, code="OUTCOME_UNKNOWN", exit_code=7, observed="operation", **operation)],
             True),
            # no operation, and the binding is `active`: no new release
            ("bindings", "active", True, [],
             [dict(still, code="OK", exit_code=0, observed="bindings", state="active")], True),
            # no operation, and the binding is not listed: not held, and not released
            ("bindings", "absent", True, [],
             [{"outcome": "not_listed", "code": "OK", "exit_code": 0, "observed": "bindings",
               "state": h2.ABSENT}], False),
            # The close alone: it gets the uncertain answer itself, and does not observe it.
            ("operation", "released", False, [many(0), many(2)], [], True),
            ("bindings", "absent", False, [many(0), many(2)], [], True),
        )
        for means, says, stopped, released, later, held in rows:
            with self.subTest(means=means, says=says, stop_goal=stopped):
                self.fresh()
                stub = STUB.replace(default, f'mode = "uncertain:{many(1)}:{means}:{says}" if')
                self.stub.write_text(f"#!{sys.executable} -IB\n{stub}", encoding="utf-8")
                self.stub.chmod(0o700)
                argv = ["--heimdall-bin", str(self.stub), "--scratch-root", str(self.root)]
                for goal in access + stop * stopped:
                    argv += ["--goal", goal]
                stdout = io.StringIO()
                with patch.dict(os.environ, self.environment), contextlib.redirect_stdout(stdout):
                    status = h2.main(argv)
                # Whatever the close then observed, the run fails: a release was uncertain.
                self.assertEqual(status, 1)
                summary = json.loads(stdout.getvalue())
                self.assertEqual([task["success"] for task in summary["tasks"]],
                                 [True, True, True] + [False] * stopped)
                # `released` names only what was released. A binding found not listed
                # is in neither list of the close: its attempts say what it is.
                self.assertEqual(summary["close"], {"released": released,
                                                    "held": [many(1)] if held else []})
                self.assertEqual(sorted(summary["close"]), ["held", "released"])
                first = dict(unknown, by="stop" if stopped else "close",
                             **(operation if means == "operation" else {}))
                self.assertEqual(summary["release_attempts"], {many(1): {"held": held, "attempts": [
                    first, *(dict(attempt, by="close") for attempt in later)]}})
                if stopped:
                    self.assertEqual(summary["tasks"][3]["outcome_unknown"],
                                     [{key: value for key, value in dict(first, binding_id=many(1)).items()
                                       if key not in ("outcome", "by")}])
                # The uncertain release was sent once, and a second one only after its
                # operation said that the first did not happen.
                self.assertEqual(sum(call == ["access", "release", many(1)] for call in self.calls()),
                                 2 if says == "never-ran" else 1)


    @unittest.skipUnless(os.name == "posix", "the stub is started through its interpreter line")
    def test_main_exits_1_after_a_request_with_no_answer_and_names_it(self):
        # M07 W6b as a whole run: `access ensure` brings no answer, then a stop goal,
        # then the close.
        found = "binding_second"
        default = 'mode = "normal" if'
        wait = ["operation", "wait", "op_fixture"]
        late = {"by": "access", "outcome": "unanswered", "code": None, "exit_code": None,
                "fault": "timed_out", "detail": "a CLI call ran past its time limit"}
        named = {"operation_id": "op_fixture"}
        ok = {"code": "OK", "exit_code": 0, "observed": "bindings"}
        still = dict(ok, outcome="still_unknown", listed=[])
        unfinished = dict(named, outcome="still_unknown", code="OK", exit_code=5, observed="operation")
        seen = self.watched(2.0, limited=(["access", "ensure"],))
        # (the stub's mode, the profile and the goal's fields; the request's own
        #  attempt; the attempts after it; whether the stop goal was met; the calls
        #  after the request; whether the request is still uncertain)
        rows = (
            # It stayed without a word, and the list never names a binding for the
            # work: the stop and the close each observe once, and the request is still
            # unknown and named.
            (f"work:{found}:none", "silent", {}, late,
             [dict(still, by="stop"), dict(still, by="close")], False,
             [["inspect", "bindings"]] * 2, True),
            # The list names one: the stop goal holds and releases it, and the request
            # is settled. The run still fails: a request brought no answer.
            (f"work:{found}:active", "silent", {}, late,
             [dict(ok, by="stop", outcome="binding_found", listed=[found], bindings=[found])], True,
             [["inspect", "bindings"], ["access", "release", found]], False),
            # It named an operation before it stayed, and that operation never ends.
            ("never", "late", {"timeout_ms": 1}, dict(late, code="ACCEPTED", **named),
             [dict(unfinished, by="stop"), dict(unfinished, by="close")], False, [wait] * 2, True),
        )
        for mode, profile, fields, own, later, stopped, calls, uncertain in rows:
            with self.subTest(mode=mode, profile=profile):
                self.fresh()
                del seen[:]
                stub = STUB.replace(default, f'mode = "{mode}" if')
                self.stub.write_text(f"#!{sys.executable} -IB\n{stub}", encoding="utf-8")
                self.stub.chmod(0o700)
                argv = ["--heimdall-bin", str(self.stub), "--scratch-root", str(self.root)]
                for goal in (self.access(profile, task="late", **fields), {"goal": "stop"}):
                    argv += ["--goal", json.dumps(goal)]
                stdout = io.StringIO()
                with patch.dict(os.environ, self.environment), contextlib.redirect_stdout(stdout):
                    status = h2.main(argv)
                self.assertEqual(status, 1)
                summary = json.loads(stdout.getvalue())
                self.assertEqual([task["success"] for task in summary["tasks"]], [False, stopped])
                self.assertEqual((summary["close"], summary["release_attempts"]),
                                 ({"released": [], "held": []}, {}))
                request_id = seen[0][7]
                self.assertEqual(summary["request_attempts"], {request_id: {
                    "call": "access ensure", "profile": profile, "work_id": "work-1",
                    "uncertain": uncertain, "attempts": [own, *later]}})
                self.assertEqual([entry["request_id"]
                                  for entry in summary["tasks"][0]["requests_unanswered"]], [request_id])
                self.assertEqual([entry["request_id"]
                                  for entry in summary["tasks"][1]["requests_still_unknown"]],
                                 [request_id] * uncertain)
                # The request was sent once. Every call after it is an observation, or
                # the release of the binding an observation showed.
                self.assertEqual([command[:3] for command in seen[1:]], calls)

@unittest.skipUnless(os.environ.get("HEIMDALL_HARNESS_SMOKE_BIN"), "fixture debug binary not supplied")
class DiscoverySmoke(unittest.TestCase):
    def test_the_table_uses_only_codes_the_installed_binary_lists(self):
        # `schema show codes` needs no runtime and starts none.
        temp = tempfile.TemporaryDirectory(prefix="heimdall-h2-smoke-",
                                           dir="/tmp" if os.name == "posix" else None)
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve()
        environment = {}
        for key, name in (("HOME", "acct"), ("HEIMDALL_HOME", "hm"), ("HEIMDALL_TEST_SSH_HOME", "sshh")):
            (root / name).mkdir()
            environment[key] = str(root / name)
        (root / "sshh" / "etc-ssh").mkdir()
        environment["HEIMDALL_TEST_MGMT_STORE"] = f"fixture-file:{root / 'mgmt-store'}"
        environment["HEIMDALL_TEST_IROH_KEY_STORE"] = str(root / "iroh-key-store")
        if os.name == "nt":
            environment["SystemRoot"] = os.environ["SystemRoot"]
        planner = h2.Planner([os.environ["HEIMDALL_HARNESS_SMOKE_BIN"]], root, environment)
        record = h2.run_goal(planner, {"goal": "discover"})
        self.assertTrue(record["success"], record)
        self.assertGreater(record["discovery_bytes"], 0)
        self.assertTrue({row.code for row in h2.TRANSITIONS if row.code.isupper()}
                        <= planner.installed_codes.keys())
        # The frozen table of exit classes is the installed table, code for code. One
        # answer is checked against another class, as documented: `ACCEPTED` is a
        # success (0) only for a caller that asked asynchronously, which H2 never does.
        self.assertEqual(h2.EXIT_CLASSES, planner.installed_codes)
        accepted = h2.Reading("ACCEPTED", "observe", None, {"code": "ACCEPTED"}, 5)
        self.assertEqual(h2.documented_exit(accepted, planner.installed_codes), (5, "ACCEPTED"))
        self.assertEqual(sorted(path.name for path in (root / "hm").iterdir()), [])
        for name in ("mgmt-store", "iroh-key-store"):
            self.assertFalse(os.path.lexists(root / name), name)


if __name__ == "__main__":
    unittest.main()
