import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch


HARNESS = runpy.run_path(str(Path(__file__).resolve().parents[1] / "harness.py"))
Journey = HARNESS["Journey"]
Metrics = HARNESS["Metrics"]
check_reply = HARNESS["check_reply"]
run_task = HARNESS["run_task"]
CODE_ROWS = [{"code": "ACCESS_READY", "exit_code": 0}]


def json_line(value):
    return (json.dumps(value) + "\n").encode("utf-8")


STUB = r'''
import json
import os
from pathlib import Path
import sys

mode, json_flag, non_interactive, *args = sys.argv[1:]
assert (json_flag, non_interactive) == ("--json", "--non-interactive")
root = Path.cwd()
for key, directory in (("HOME", "home"), ("HEIMDALL_HOME", "heimdall-home"),
                       ("HEIMDALL_TEST_SSH_HOME", "ssh-home")):
    assert Path(os.environ[key]).resolve() == root / directory
(root / "heimdall-home-seen").write_text(os.environ["HEIMDALL_HOME"], encoding="utf-8")
assert "SSH_AUTH_SOCK" not in os.environ and "H1_TEST_FOREIGN_ENV" not in os.environ
assert not any((root / "ssh-home" / "etc-ssh").iterdir())
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

op = "op_fixture"
binding = "binding_fixture"
observed = "binding_observed"  # the binding of the operation `operation wait` observes
rows = [{"code": "ACCESS_READY", "exit_code": 0}]


def emit(**fields):
    print(json.dumps(dict(schema_version="1", **fields)))


def reply(code="OK", data=None, state="succeeded", **fields):
    emit(code=code, data=data, state=state, **fields)


if args == ["schema", "show", "codes"]:
    reply(data={"codes": rows})
elif args == ["inspect", "capabilities"]:
    if mode == "malformed":
        print("{} {}")
    else:
        reply(data={"capabilities": ["operations/1"], "codes": rows, "schemas": ["envelope"]})
elif args[:2] == ["access", "ensure"]:
    options = args[8:]
    assert args[2] == "--profile" and args[4] == "--work-id" and args[6] == "--request-id"
    if options == ["--timeout-ms", "1"]:
        reply("ACCEPTED", state="running", operation_id=op,
              next={"action": "observe", "operation_id": op})
        sys.exit(0 if mode == "wrong-exit" else 5)
    if options == ["--require-unattended"]:
        reply("CAPABILITY_UNAVAILABLE", state="failed",
              data={"error": {"code": "CAPABILITY_UNAVAILABLE",
                              "effect_status": "partial" if mode == "effect" else "none"}})
        sys.exit(4)
    if options == ["--pair", "destination:account"]:
        reply("INTERACTION_REQUIRED", state="awaiting_approval", operation_id=op,
              next={"action": "interact", "decision_ref": "dec_fixture", "operation_id": op})
        sys.exit(3)
    assert not options
    reply("ACCESS_READY", {"binding_id": binding}, operation_id=op,
          next={"action": "use_binding", "binding_id": binding})
elif args == ["operation", "wait", op, "--timeout-ms", "30000"]:
    reply(data={"operation_id": "op_other" if mode == "wrong-operation" else op,
                "state": "succeeded", "code": "ACCESS_READY", "result": {"binding_id": observed}},
          operation_id=op)
elif args[:5] == ["operation", "events", "--operation", op, "--follow"]:
    if args[5:] == ["--max-events", "1", "--cursor=cursor-fixture"]:
        reply(data={"subscription": 1, "cursor": "cursor-next", "snapshot": None}, state="running")
        emit(type="operation_state_changed", event_id="evt_fixture", cursor="cursor-next",
             operation_id="op_other" if mode == "bad-event" else op, payload={"state": "succeeded"})
    else:
        assert args[5:] == ["--max-events", "0"]
        snapshot = {"data": {"operation": {"operation_id": op, "state": "awaiting_approval"}}}
        reply(data={"subscription": 1, "cursor": "cursor-fixture", "snapshot": snapshot}, state="running")
elif args[:2] == ["access", "release"] and args[2:] in ([binding], [observed]):
    reply(data={"binding_id": binding if mode == "other-binding" else args[2],
                "outcome": {"outcome": "released", "remaining_references": 0}})
elif args[0] == "run":
    assert args[1] == "--profile" and args[3] == "--work-id" and args[5] == "--request-id"
    assert args[7] == "--" and Path(args[8]).is_absolute() and args[9:] == ["fixture-argument"]
    print("different-child" if mode == "child-failure" else "h1-fixture-child")
else:
    sys.exit(2)
'''


def fixture_root(test):
    temp = tempfile.TemporaryDirectory(prefix="heimdall-h1-", dir="/tmp" if os.name == "posix" else None)
    test.addCleanup(temp.cleanup)
    root = Path(temp.name).resolve()
    (root / "home").mkdir()
    (root / "heimdall-home").mkdir()
    (root / "ssh-home" / "etc-ssh").mkdir(parents=True)
    return root


class WindowsEnvironmentTests(unittest.TestCase):
    def test_windows_environment_uses_only_system_and_fixture_paths(self):
        windows = r"D:\Windows"
        home = r"C:\fixture root\home"
        inherited = {"PATH": r"C:\extra", "SSH_AUTH_SOCK": "parent-agent"}
        with patch.dict(os.environ, inherited):
            self.assertEqual(HARNESS["windows_environment"](windows, home), {
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
        with self.assertRaisesRegex(HARNESS["HarnessError"], "SystemRoot"):
            HARNESS["windows_environment"](r"D:Windows", home)


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.root = fixture_root(self)
        self.stub = self.root / "heimdall.py"
        self.stub.write_text(STUB, encoding="utf-8")

    def journey(self, mode="normal"):
        return Journey([sys.executable, "-I", "-B", str(self.stub), mode], self.root)

    def calls(self):
        return [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]

    def test_discovery_counts_stdout_bytes_and_drops_parent_environment(self):
        with patch.dict(os.environ, SSH_AUTH_SOCK="fixture-parent", H1_TEST_FOREIGN_ENV="discard"):
            result = run_task("discover", self.journey().discover)
        base = {"schema_version": "1", "code": "OK"}
        wire = json_line(dict(base, data={"codes": CODE_ROWS}, state="succeeded")) + json_line(
            dict(base, data={"capabilities": ["operations/1"], "codes": CODE_ROWS,
                             "schemas": ["envelope"]}, state="succeeded"))
        self.assertTrue(result["success"], result)
        self.assertEqual(result["discovery_bytes"], len(wire) + (2 if os.linesep == "\r\n" else 0))
        self.assertEqual(result["calls"], result["round_trips"])
        self.assertEqual(result["calls"], 2)
        self.assertEqual(self.calls(), [["schema", "show", "codes"], ["inspect", "capabilities"]])

    def test_standard_fixture_tasks_are_procedural(self):
        journey = self.journey()
        results = [run_task("covered", journey.covered, "covered"),
                   run_task("timeout", journey.timeout, "slow"),
                   run_task("release", journey.release),
                   run_task("capability-refusal", journey.capability_refusal, "existing-access")]
        # `release` drops every binding the earlier tasks were given: the covered one and
        # the one of the operation `timeout` observed, one call for each, the newest first.
        self.assertEqual([result["calls"] for result in results], [1, 2, 2, 1])
        for result in results:
            self.assertTrue(result["success"], result)
            self.assertEqual(result["discovery_bytes"], 0)
            self.assertEqual(result["human_handoffs"], 0)
            self.assertEqual(result["invalid_retries"], 0)
            self.assertGreaterEqual(result["wall_time_ms"], 0)
        calls = self.calls()
        self.assertEqual(calls[1][-2:], ["--timeout-ms", "1"])
        self.assertEqual(calls[2], ["operation", "wait", "op_fixture", "--timeout-ms", "30000"])
        self.assertEqual(calls[3:5], [["access", "release", "binding_observed"],
                                      ["access", "release", "binding_fixture"]])
        self.assertEqual(calls[5][-1], "--require-unattended")
        self.assertEqual(journey.bindings, [])
        again = run_task("release", journey.release)  # nothing is held now
        self.assertEqual((again["success"], again["calls"]), (False, 0))
        requests = [args[7] for args in calls if args[:2] == ["access", "ensure"]]
        self.assertEqual(len(requests), len(set(requests)))
        self.assertEqual(results[-1]["detail"], "CAPABILITY_UNAVAILABLE (effect none)")

    def test_approval_handoff_replays_event_and_excludes_human_time(self):
        def handoff(operation, decision):
            self.assertEqual((operation, decision), ("op_fixture", "dec_fixture"))
            self.assertEqual(self.calls()[-1][-2:], ["--max-events", "0"])
            return True

        with patch.object(HARNESS["time"], "monotonic", side_effect=(0, .02, 1.02, 1.05)):
            result = run_task("approval", self.journey().approval, "wider", "destination:account", handoff)
        self.assertTrue(result["success"], result)
        self.assertEqual(result["calls"], 4)
        self.assertEqual(result["human_handoffs"], 1)
        self.assertEqual(result["wall_time_ms"], 50)
        self.assertEqual(self.calls()[2][-3:], ["--max-events", "1", "--cursor=cursor-fixture"])

    def test_release_drops_the_binding_of_an_approved_or_observed_operation(self):
        # M07-W3-R01 in H1: `approval` and `timeout` each end holding their operation's
        # binding, with no `covered` task before them.
        for task, args in (("timeout", ("slow",)),
                           ("approval", ("wider", "destination:account", lambda *_: True))):
            with self.subTest(task=task):
                journey = self.journey()
                self.assertTrue(run_task(task, getattr(journey, task), *args)["success"])
                released = run_task("release", journey.release)
                self.assertEqual((released["success"], released["calls"]), (True, 1), released)
                self.assertEqual(self.calls()[-1], ["access", "release", "binding_observed"])
                self.assertEqual(journey.bindings, [])
        # A release answered for another binding fails, and that binding stays held.
        journey = self.journey("other-binding")
        self.assertTrue(run_task("timeout", journey.timeout, "slow")["success"])
        self.assertFalse(run_task("release", journey.release)["success"])
        self.assertEqual(journey.bindings, ["binding_observed"])

    def test_bind_run_requires_child_marker(self):
        child = [str(self.stub), "fixture-argument"]
        result = run_task("bind-run", self.journey().bind_run, "covered", child)
        self.assertTrue(result["success"], result)
        self.assertEqual(result["calls"], 1)
        result = run_task("bind-run", self.journey("child-failure").bind_run, "covered", child)
        self.assertFalse(result["success"])
        self.assertIn("fixture child", result["detail"])

    def test_bad_output_fails_without_retry(self):
        cases = (
            ("discover", "malformed", (), 2),
            ("timeout", "wrong-exit", ("slow",), 1),
            ("timeout", "wrong-operation", ("slow",), 2),
            ("capability-refusal", "effect", ("existing-access",), 1),
            ("approval", "bad-event", ("wider", "destination:account", lambda *_: True), 3),
        )
        for task, mode, args, expected_calls in cases:
            with self.subTest(task=task, mode=mode):
                script = getattr(self.journey(mode), task.replace("-", "_"))
                result = run_task(task, script, *args)
                self.assertFalse(result["success"], result)
                self.assertEqual(result["calls"], expected_calls)
                self.assertEqual(result["invalid_retries"], 0)

    def test_missing_fixture_home_prevents_spawn(self):
        (self.root / "ssh-home" / "etc-ssh").rmdir()
        result = run_task("discover", self.journey().discover)
        self.assertFalse(result["success"])
        self.assertEqual(result["calls"], 0)
        self.assertFalse((self.root / "calls.jsonl").exists())

    @unittest.skipUnless(os.name == "posix", "requires fixture symlinks")
    def test_redirected_fixture_home_prevents_spawn(self):
        (self.root / "heimdall-home").rmdir()
        (self.root / "heimdall-home").symlink_to(self.root / "home", target_is_directory=True)
        result = run_task("discover", self.journey().discover)
        self.assertFalse(result["success"])
        self.assertEqual(result["calls"], 0)
        self.assertFalse((self.root / "calls.jsonl").exists())

    @unittest.skipUnless(os.name == "posix", "requires fixture symlinks")
    def test_homes_keep_the_spelling_of_the_given_root(self):
        # A runtime is found under the spelling of the Heimdall home it was started with,
        # and a temporary directory is often reached through a link (macOS /tmp, /var).
        aliases = tempfile.TemporaryDirectory(prefix="heimdall-h1-alias-", dir="/tmp")
        self.addCleanup(aliases.cleanup)
        alias = Path(aliases.name).resolve() / "root"
        alias.symlink_to(self.root, target_is_directory=True)
        journey = Journey([sys.executable, "-I", "-B", str(self.stub), "normal"], alias)
        result = run_task("discover", journey.discover)
        self.assertTrue(result["success"], result)
        seen = (self.root / "heimdall-home-seen").read_text(encoding="utf-8")
        self.assertEqual(seen, str(alias / "heimdall-home"))

    def test_cli_marks_driver_tasks_skipped_and_prints_one_summary(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = HARNESS["main"]([
                "--heimdall-bin", str(self.stub), "--scratch-root", str(self.root),
                "--task", "approval", "--task", "bind-run",
            ])
        self.assertEqual(status, 1)
        self.assertEqual(len(stdout.getvalue().splitlines()), 1)
        summary = json.loads(stdout.getvalue())
        self.assertEqual(summary["harness"], "H1")
        for task in summary["tasks"]:
            self.assertTrue(task["skipped"], task)
            self.assertEqual(task["calls"], 0)
            self.assertIn("U5h", task["detail"])


@unittest.skipUnless(os.environ.get("HEIMDALL_HARNESS_SMOKE_BIN"), "fixture debug binary not supplied")
class DiscoverySmoke(unittest.TestCase):
    def test_real_discovery_without_runtime(self):
        journey = Journey([os.environ["HEIMDALL_HARNESS_SMOKE_BIN"]], fixture_root(self))
        metrics = Metrics("discover")
        codes = check_reply(*journey.reply(metrics, "schema", "show", "codes"), 0, "OK")
        self.assertIn(CODE_ROWS[0], [{key: row[key] for key in CODE_ROWS[0]}
                                    for row in codes["data"]["codes"]])
        check_reply(*journey.reply(metrics, "inspect", "capabilities"), 5, "SERVICE_UNAVAILABLE")
        self.assertEqual(metrics.calls, 2)
        self.assertGreater(metrics.discovery_bytes, 0)
