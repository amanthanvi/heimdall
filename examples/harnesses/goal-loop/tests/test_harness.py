import ast
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
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
    "exit_code": 9,
}

# A stand-in `heimdall`: `stub.py [MODE] --json --non-interactive <command...>`. It checks
# the launch environment, logs each command, and answers from fixed data. For `run` it is
# the child itself: it writes the run record, prints one line and waits for its input to end.
# Mode `exit:CODE=N` ends every answer whose envelope code is CODE with exit N instead of
# the documented class, the envelope unchanged.
STUB = r'''
import json
import os
from pathlib import Path
import sys
import time

args = sys.argv[1:]
mode = "normal" if args[0] == "--json" else args.pop(0)
assert args[:2] == ["--json", "--non-interactive"], args
args = args[2:]
root = Path.cwd()
for key, directory in (("HOME", "acct"), ("HEIMDALL_HOME", "hm"), ("HEIMDALL_TEST_SSH_HOME", "sshh")):
    assert Path(os.environ[key]).resolve() == root / directory, key
assert "SSH_AUTH_SOCK" not in os.environ and "H2_TEST_FOREIGN_ENV" not in os.environ
assert [key for key in os.environ if key.startswith("HEIMDALL_")] == ["HEIMDALL_HOME", "HEIMDALL_TEST_SSH_HOME"]
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
    emit("OK", 0, {"codes": [{"code": code} for code in listed]}, state="succeeded")
elif args[:2] == ["access", "ensure"]:
    assert args[2] == "--profile" and args[4] == "--work-id" and args[6] == "--request-id", args
    profile, options = args[3], args[8:]
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
    if mode == "denied":
        view("CAPABILITY_UNAVAILABLE", "failed", "none", {"error": {}}, exit_code=4)
    if mode == "still-unknown":
        view("OUTCOME_UNKNOWN", "outcome_unknown", "unknown", {"error": {}}, exit_code=7)
    # How many observations find the operation unfinished before it ends.
    unfinished = int(mode[11:]) if mode.startswith("unfinished-") else UNFINISHED.get(mode, 0)
    if unfinished and count("wait") < unfinished:
        view(None, "awaiting_approval", "none", None, {"action": "observe", "operation_id": OP}, 5)
    view("ACCESS_READY", "succeeded", "applied", {"binding_id": BINDING})
elif args[:2] == ["access", "release"]:
    assert len(args) == 3 and (args[2] in (BINDING, SECOND) or args[2].startswith("binding_many_")), args
    answered = "binding_other" if mode == "other-binding" else args[2]
    emit("OK", 0, {"binding_id": answered, "outcome": {"outcome": "released"}}, state="succeeded")
elif args[0] == "run":
    assert args[1] == "--profile" and args[3] == "--work-id" and args[5] == "--request-id", args
    assert args[7] == "--meta-file" and args[9] == "--" and Path(args[10]).is_absolute(), args
    if mode in ("refused-launch", "refused-launch-exit-0"):
        refuse("CAPABILITY_UNAVAILABLE", "narrow_request", 4 if mode == "refused-launch" else 0,
               stream=sys.stderr)
    with open(args[8], "x", encoding="utf-8") as meta:
        print(json.dumps({"type": "launching", "schema_version": "1", "attempt": 1,
                          "executable": args[10], "operation_id": OP,
                          "binding_id": SECOND if mode == "second-binding" else BINDING,
                          "pid": 1 if mode == "other-pid" else os.getpid(),
                          "consumer_overrides": []}), file=meta)
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
        # not fit, and every code a row acts on has a documented exit class.
        self.assertEqual(set(h2.CALLING), set(h2.STATES) - {"stopped", "failed", "inconsistent",
                                                              "unresolved"})
        self.assertEqual([row.states for row in h2.TRANSITIONS if row.code == h2.MISMATCH],
                         [h2.CALLING])
        self.assertEqual({row.code for row in h2.TRANSITIONS if row.code.isupper()},
                         {key for key in h2.EXIT_CLASSES if isinstance(key, str)})
        for key, exit_class in h2.EXIT_CLASSES.items():
            self.assertIn(exit_class, range(8), key)
            if not isinstance(key, str):
                self.assertTrue(any((row.code, row.action) == key for row in h2.TRANSITIONS), key)
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

    def test_a_code_without_its_typed_fields_has_no_row(self):
        reading = h2.Reading("ACCESS_READY", "use_binding", None, {"code": "ACCESS_READY", "next": {}})
        after, row = h2.transition(h2.State("start"), reading)
        self.assertIsNone(row)
        self.assertEqual(after.name, "failed")

    def test_the_call_set_names_no_decision_or_owner_command(self):
        for name, call in h2.load_call_set(["/nonexistent"]).items():
            words = [part for part in call["argv"] if not part.startswith(("{", "-"))]
            self.assertIn(words[0], ("schema", "access", "operation", "run"), name)
            for word in words:
                self.assertNotIn(word, ("decision", "approve", "deny", "time", "confirm", "resume",
                                        "allow", "stop", "tui", "setup", "inspect"), name)


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
        # A release in the wrong exit class leaves its binding held: a later stop asks again.
        planner = self.planner("exit:OK=1")
        self.assertTrue(h2.run_goal(planner, self.access())["success"])
        stopped = h2.run_goal(planner, {"goal": "stop"})
        self.assertFalse(stopped["success"])
        self.assertEqual((stopped["final_state"], stopped["held"]),
                         (inconsistent("OK", 1), ["binding_fixture"]))

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
        planner = self.planner("other-binding")
        self.assertTrue(h2.run_goal(planner, self.access())["success"])
        stopped = h2.run_goal(planner, {"goal": "stop"})
        self.assertFalse(stopped["success"])
        self.assertIn("another binding", stopped["detail"])
        self.assertEqual((stopped["final_state"]["state"], stopped["held"]), ("ready", ["binding_fixture"]))

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
        # A home reached through a link that stays inside the root is passed as it was given.
        inside = self.root / "alias"
        inside.symlink_to(self.root / "hm", target_is_directory=True)
        env = h2.launch_environment(self.root, dict(self.environment, HEIMDALL_HOME=str(inside)))
        self.assertEqual(env["HEIMDALL_HOME"], str(inside))
        self.assertEqual(sorted(env), ["HEIMDALL_HOME", "HEIMDALL_TEST_SSH_HOME", "HOME", "LANG",
                                       "PATH", "TERM"])

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
        for task in summary["tasks"]:
            for field in ("calls", "round_trips", "human_handoffs", "invalid_retries",
                          "wall_time_ms", "discovery_bytes", "detail", "skipped", "final_state",
                          "held"):
                self.assertIn(field, task)


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
        if os.name == "nt":
            environment["SystemRoot"] = os.environ["SystemRoot"]
        planner = h2.Planner([os.environ["HEIMDALL_HARNESS_SMOKE_BIN"]], root, environment)
        record = h2.run_goal(planner, {"goal": "discover"})
        self.assertTrue(record["success"], record)
        self.assertGreater(record["discovery_bytes"], 0)
        self.assertTrue({row.code for row in h2.TRANSITIONS if row.code.isupper()}
                        <= planner.installed_codes.keys())
        # The exit classes H2 checks are the installed table's own. One differs, as
        # documented: `ACCEPTED` is a success (0) only for a caller that asked
        # asynchronously, which H2 never does.
        ours = {code: exit_class for code, exit_class in h2.EXIT_CLASSES.items() if isinstance(code, str)}
        theirs = {code: planner.installed_codes[code] for code in ours}
        self.assertEqual((ours.pop("ACCEPTED"), theirs.pop("ACCEPTED")), (5, 0))
        self.assertEqual(ours, theirs)
        self.assertEqual(sorted(path.name for path in (root / "hm").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
