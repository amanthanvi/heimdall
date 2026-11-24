import ast
import contextlib
import datetime
import importlib.util
import io
import json
import os
from pathlib import Path, PureWindowsPath
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
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
# Every entry of the list names a profile and a creation time (M07 W6c). By default
# they are the profile of the newest request the stub was sent, and the moment the list
# is read. A name in NAMES written `NAME/other` has another profile, `NAME/before` a
# creation time long before any request, and `NAME/undated` none.
# For `operation wait`, `sleep:wait:` makes the first wait stay without a word, and
# `sleep:wait-garbled:` makes it print something that is no envelope and end; later
# waits answer as the mode says. Mode `ready-wrong-exit` answers a wait with a view that
# succeeded and names its binding, with exit 3.
# M07 W7: `sleep:wait-unavailable:` refuses the first wait with `SERVICE_UNAVAILABLE` (exit 5),
# `sleep:wait-wrong:` answers it with a view still `running` and exit 0 (the wrong class),
# and `sleep:wait-unknown:` with a view whose own outcome is unknown (exit 7); later waits
# answer as the mode says. Profile `uncertain-none` is answered `OUTCOME_UNKNOWN` naming no
# operation, with effect `none` (M07-W6-R03's probe). The stub logs when each request
# arrived, and for which profile; a name in NAMES written `NAME/made-N` was made just after
# the Nth request arrived, for that request's profile (M07-W6-R02's probes). Mode `spawned`
# writes the Windows `spawned` run record after `launching`, as the stub always does on
# Windows.
# M07 W8c: profile `unsupported` refuses `access ensure` with `UNSUPPORTED_CLIENT`, a
# published code the table has no row for (exit 5, naming its operation), and a `run` for
# profile `novel` is refused on stderr with `SOMETHING_NEW`, a code no table has.
# M07 W8 (M07-W7-R03): mode `spawn-child` is the launch as Heimdall makes it on Windows,
# on either platform. The stub writes `launching`, spawns the goal's child with its own
# input (a batch script on Windows as Rust's std starts one: the system directory's
# cmd.exe), writes `spawned` with the child's PID and the PID to the file `spawned-pid`,
# prints its line, and exits with the child's exit code once it has ended. The child's
# output goes nowhere (Heimdall's child shares Heimdall's): a child that outlives the stop
# then cannot keep the harness waiting on its pipes, and the test sees it still running.
# Mode `spawn-child-mute` is the same launch with a child that ends before it is up: the
# stub prints no line, and exits with the child's exit code once it has ended.
# M07 W8e: SAYS `live` in mode `work:NAMES:SAYS` is `active` as Heimdall's list would show
# it: a binding the harness released (an `access release` of it earlier in `calls.jsonl`)
# is listed `released` from then on. A name in NAMES that ends `@K` (after any `/` tie) is
# listed only in the first K reads of the list, then not at all (it expired, or another
# caller released it). Profiles `bad-operation` and `bad-decision` answer `access ensure`
# with a code that has a row, and one typed field present but invalid: `ACCEPTED` whose
# `next.operation_id` is `op bad` (the envelope's own `op_fixture` is valid, exit 5), and
# `APPROVAL_REQUIRED` whose `next.decision_ref` is `dec bad` (`next.operation_id`
# `op_fixture`, exit 3); `bad-binding` is the same for `ACCESS_READY` (M07-W8-R03).
STUB = r'''
import json
import os
from pathlib import Path
import subprocess
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
         "OPERATION_CANCELLED", "REQUEST_CONFLICT", "OUTCOME_UNKNOWN", "NOT_FOUND",
         "DESTINATION_UNREACHABLE", "TIME_UNCERTAIN", "SERVICE_UNAVAILABLE", "STATE_UNAVAILABLE",
         "BACKPRESSURE"]
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
    (root / "last-profile").write_text(profile)
    with (root / "received").open("a", encoding="utf-8") as received:  # each request's arrival
        print(time.time_ns(), profile, file=received)
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
    if profile == "unsupported":
        refuse("UNSUPPORTED_CLIENT", "change_client", 5)
    if profile == "bad-binding":
        emit("ACCESS_READY", 0, {}, {"action": "use_binding", "binding_id": "../../not-a-binding"})
    if profile == "bad-operation":
        emit("ACCEPTED", 5, {}, {"action": "observe", "operation_id": "op bad"}, state="running",
             operation_id=OP)
    if profile == "bad-decision":
        refuse("APPROVAL_REQUIRED", "observe", 3, decision_ref="dec bad", operation_id=OP)
    if profile == "missing":
        refuse("NOT_FOUND", "fix_request", 2)
    if profile == "uncertain":
        refuse("OUTCOME_UNKNOWN", "reconcile", 7, effect="unknown", operation_id=OP)
    if profile == "uncertain-none":  # M07-W6-R03's probe: no operation, and effect `none`
        following = {"action": "reconcile"}
        emit("OUTCOME_UNKNOWN", 7, {"error": {"code": "OUTCOME_UNKNOWN", "effect_status": "none",
                                              "next": following}}, following, state="outcome_unknown")
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
    if sleeps == "always" or sleeps == "wait" and count("slept-wait") == 0:
        time.sleep(60)
    if sleeps == "wait-garbled" and count("slept-wait") == 0:
        print("this is no envelope", flush=True)
        sys.exit(0)
    if sleeps == "wait-unavailable" and count("slept-wait") == 0:
        refuse("SERVICE_UNAVAILABLE", "retry_after", 5)
    if sleeps == "wait-wrong" and count("slept-wait") == 0:  # still running, yet exit 0
        view(None, "running", "unknown", None)
    if sleeps == "wait-unknown" and count("slept-wait") == 0:
        view("OUTCOME_UNKNOWN", "outcome_unknown", "unknown", {"error": {}}, exit_code=7)
    if mode == "ready-wrong-exit":
        view("ACCESS_READY", "succeeded", "applied", {"binding_id": BINDING}, exit_code=3)
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
              "twice": ["active", "released"], "live": ["active"]}.get(says, [])
    # what the harness released before this read, and how many reads came before it
    logged = [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()]
    gone = {call[2] for call in logged if call[:2] == ["access", "release"]}
    reads = logged.count(["inspect", "bindings"]) - 1
    if mode.startswith("work:") and says == "wrong-exit":
        states = ["active"]
    asked = (root / "last-profile").read_text() if (root / "last-profile").exists() else "covered"
    now = time.time()
    made = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + ".%06dZ" % (int(now * 1e6) % 1000000)

    def entry(name, work, state):
        name, _, tie = name.partition("/")
        stamp, profile = made, asked
        if tie.startswith("made-"):  # made just after the Nth request arrived, for its profile
            arrived, profile = (root / "received").read_text().splitlines()[int(tie[5:]) - 1].split()
            moment = int(arrived) + 1000000
            stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(moment // 10**9)) + ".%09dZ" % (
                moment % 10**9)
        listed = {"binding_id": name, "grant_id": "grant_fixture", "work_id": work,
                  "profile": "someone-else" if tie == "other" else profile, "profile_revision": 1,
                  "state": state, "created_at": "2001-02-03T04:05:06Z" if tie == "before" else stamp}
        if tie == "undated":
            del listed["created_at"]
        return listed
    listed = [entry("binding_bystander", "work-bystander", "active")]
    for name in names:
        name, _, kept = name.partition("@")
        if says == "live" and kept and reads >= int(kept):
            continue
        listed += [entry(name, "work-1", "released" if says == "live" and name.partition("/")[0] in gone
                         else state) for state in states]
    emit("OK", 4 if says == "wrong-exit" else 0, {"bindings": listed}, state="succeeded")
elif args[0] == "run":
    assert args[1] == "--profile" and args[3] == "--work-id" and args[5] == "--request-id", args
    assert args[7] == "--meta-file" and args[9] == "--" and Path(args[10]).is_absolute(), args
    (root / "last-profile").write_text(args[2])
    if sleeps == "run":
        time.sleep(60)
    if args[2] == "garbled":
        print("this is no envelope", file=sys.stderr, flush=True)
        sys.exit(1)
    if args[2] == "novel":
        refuse("SOMETHING_NEW", "report", 1, stream=sys.stderr)
    if mode in ("refused-launch", "refused-launch-exit-0"):
        refuse("CAPABILITY_UNAVAILABLE", "narrow_request", 4 if mode == "refused-launch" else 0,
               stream=sys.stderr)
    with open(args[8], "x", encoding="utf-8") as meta:
        print(json.dumps({"type": "launching", "schema_version": "1", "attempt": 1,
                          "executable": args[10], "operation_id": OP,
                          "binding_id": SECOND if mode == "second-binding" else BINDING,
                          "pid": 1 if mode == "other-pid" else os.getpid(),
                          "consumer_overrides": []}), file=meta, flush=True)
        if mode in ("spawn-child", "spawn-child-mute"):  # as Heimdall on Windows: a process of its own
            program = args[10:]
            if os.name == "nt" and program[0].lower().endswith((".bat", ".cmd")):
                program = [str(Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"),
                           "/e:ON", "/v:OFF", "/d", "/c", *program]
            spawned = subprocess.Popen(program, stdin=0, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
            (root / "spawned-pid").write_text(str(spawned.pid))
            print(json.dumps({"type": "spawned", "schema_version": "1", "pid": spawned.pid}), file=meta)
        elif os.name == "nt" or mode == "spawned":  # Windows: the child exists (here, this process)
            print(json.dumps({"type": "spawned", "schema_version": "1", "pid": os.getpid()}), file=meta)
    if sleeps == "run-recorded":
        time.sleep(60)
    if mode == "silent-child":
        sys.exit(0)
    if mode == "spawn-child-mute":
        sys.exit(spawned.wait())
    print("up", flush=True)
    if mode == "spawn-child":
        sys.exit(spawned.wait())
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
        # The operation's own outcome is unknown: the one being observed. The report
        # names the request too, which is remembered (W7).
        self.assertEqual(h2.TRACKED, h2.IN_FLIGHT + ("reconciling",))
        for name in h2.TRACKED:
            with self.subTest(state=name):
                ended = h2.Reading("OUTCOME_UNKNOWN", "none", "unknown",
                                   {"code": "OUTCOME_UNKNOWN", "request": {"request_id": "request-sample"}})
                after, row = h2.transition(sample_state(name), ended)
                self.assertIsNotNone(row)
                self.assertEqual(after, h2.State("failed", code="OUTCOME_UNKNOWN", operation_id="op_sample",
                                                 request_id="request-sample"))
                self.assertEqual(after.record(), {"state": "failed", "code": "OUTCOME_UNKNOWN",
                                                  "operation_id": "op_sample", "request_id": "request-sample"})
                # With an action no row pairs it with, there is no row, and the operation
                # is still named.
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
        # Only the states that wait on the operation of an answered request have a row for
        # the step limit (M07-W6-R01). `reconciling` ends the goal in `unresolved`; an
        # accepted operation or an approval still open ends it in `failed`, which names
        # the request and its operation.
        self.assertEqual([row.states for row in h2.TRANSITIONS if row.code == h2.BOUND],
                         [("reconciling",), h2.IN_FLIGHT])
        for name in h2.IN_FLIGHT:
            before = sample_state(name)
            limit = h2.Reading(h2.BOUND, "none", None, {"request": {"request_id": "request-sample"}})
            self.assertEqual(h2.transition(before, limit)[0].record(), {
                "state": "failed", "code": "OUTCOME_UNKNOWN", "operation_id": "op_sample",
                "request_id": "request-sample"})
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
        found, never, still, misfit = h2.FOUND, h2.NEVER_RAN, h2.STILL_OPEN, h2.MISFIT
        shared = h2.SHARED_FIND
        # (the call, the code, next.action, whether the exit class fits, typed facts, the reading)
        rows = (
            # its operation: only a terminal view of one that succeeded, and that names
            # the binding it made, is evidence of a binding
            ("observe", "ACCESS_READY", "none", True, view("applied", "succeeded"), found),
            # the same in another exit class: the binding is held all the same, and the
            # request is not settled (M07 W6c, ruled 2026-11-23)
            ("observe", "ACCESS_READY", "none", False, view("applied", "succeeded"), misfit),
            ("observe", "ACCESS_READY", "none", False, view("applied", "running"), still),
            ("observe", "ACCESS_READY", "none", False, view("applied", "succeeded", None), still),
            ("observe", "ACCESS_READY", "observe", False, view("applied", "succeeded"), still),
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
            # more than one binding can be the request's: none is (M07 W6c)
            ("work", "OK", "none", True, work(h2.SEVERAL), still),
            ("work", "OK", "none", True, {}, still),  # the list says nothing of the work
            ("work", "OK", "none", False, work(h2.NEW), misfit),
            # that one binding can be an older request's too (M07-W7-R04): it is held,
            # in either exit class, and settles nothing
            ("work", "OK", "none", True, work(h2.SHARED), shared),
            ("work", "OK", "none", False, work(h2.SHARED), shared),
            ("work", "OK", "observe", True, work(h2.SHARED), still),
            # one candidate, in a read ambiguous about another binding: nothing is
            # credited in that read, in either exit class (ruled 2026-11-23)
            ("work", "OK", "none", True, work(h2.WITHHELD), still),
            ("work", "OK", "none", False, work(h2.WITHHELD), still),
            ("work", "OK", "none", False, work(h2.SEVERAL), still),
            ("work", "OK", "none", False, work(h2.NONE_NEW), still),
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
        self.assertEqual(wanted, {found: ("succeeded",), misfit: ("succeeded",),
                                  never: ("failed", "cancelled")})
        # A binding out of its exit class is wanted as a found one is, only in another
        # class, and it is recorded as still unknown: it gives a binding and settles nothing.
        for call in h2.REQUEST_OBSERVED_BY:
            rows = {row.reading: row for row in h2.REQUEST_SAYS
                    if row.call == call and row.reading in (found, misfit)}
            self.assertEqual(rows[found]._replace(fits=False, reading=misfit), rows[misfit])
        self.assertEqual((h2.REQUEST_OUTCOMES[misfit], h2.REQUEST_OUTCOMES[shared]),
                         ("still_unknown", "still_unknown"))
        self.assertEqual((h2.SETTLED, h2.GIVING), ((found, never), (found, misfit, shared)))
        self.assertEqual(sorted(h2.REQUEST_RECORDED.values()),
                         sorted(set(h2.REQUEST_OUTCOMES.values()) - {"binding_found", "not_run"}
                                | set(h2.KEPT.values())))
        # No envelope can stand in for one of the planner's own readings.
        for own in (found, never, still, misfit, shared):
            with self.assertRaises(h2.PlannerError):
                h2.read_envelope({"schema_version": "1", "code": own})

    def test_the_list_of_bindings_is_reduced_to_the_bindings_that_can_be_the_requests(self):
        # M07 W6c (ruled 2026-11-23): a binding can be the request's own only by every
        # typed field the list offers that ties it to the request: its work, its
        # profile, and a creation time later than the moment the request was sent.
        sent = h2.instant("2026-11-23T10:00:00.5Z")
        request = {"work_id": "work-sample", "profile": "covered", "sent_at": sent}
        after, before = "2026-11-23T10:00:00.500000001Z", "2026-11-23T10:00:00.5Z"

        def entry(binding, work="work-sample", state="active", profile="covered", made=after):
            listed = {"binding_id": binding, "grant_id": "grant_sample", "work_id": work,
                      "profile": profile, "profile_revision": 1, "state": state, "created_at": made}
            return {key: value for key, value in listed.items() if value is not None}
        ok = lambda data: {"schema_version": "1", "code": "OK", "data": data, "next": None}
        # (the envelope, the request asked about; the bindings it names for that work in
        #  the state `active`, and those of them that can be the request's: None when
        #  it says nothing of the request)
        rows = (
            (ok({"bindings": [entry("binding_a"), entry("binding_b", work="work-other"),
                              entry("binding_c", state="released"), entry("binding_d")]}),
             request, ["binding_a", "binding_d"], ["binding_a", "binding_d"]),
            (ok({"bindings": [entry("binding_a")] * 2}), request, ["binding_a"], ["binding_a"]),
            # another profile: another caller's, or another request's
            (ok({"bindings": [entry("binding_a", profile="other"), entry("binding_b")]}), request,
             ["binding_a", "binding_b"], ["binding_b"]),
            (ok({"bindings": [entry("binding_a", profile=None)]}), request, ["binding_a"], []),
            # made when the request was sent, or before: not the request's
            (ok({"bindings": [entry("binding_a", made=before), entry("binding_b")]}), request,
             ["binding_a", "binding_b"], ["binding_b"]),
            (ok({"bindings": [entry("binding_a", made="2026-11-22T10:00:00Z")]}), request,
             ["binding_a"], []),
            # a creation time that is not one, or none: it cannot be tied to the request
            (ok({"bindings": [entry("binding_a", made=None)]}), request, ["binding_a"], []),
            (ok({"bindings": [entry("binding_a", made="2026-11-23T10:00:01+00:00")]}), request,
             ["binding_a"], []),
            (ok({"bindings": [entry("binding_a", made="2026-13-23T10:00:01Z")]}), request,
             ["binding_a"], []),
            (ok({"bindings": [entry("binding_a", made=1795435201)]}), request, ["binding_a"], []),
            # a request whose sending moment is not known ties no binding to it
            (ok({"bindings": [entry("binding_a")]}), dict(request, sent_at=None), ["binding_a"], []),
            (ok({"bindings": [entry("binding_b", work="work-other")]}), request, [], []),
            (ok({"bindings": []}), request, [], []),
            (ok({"bindings": [entry("binding_a", state="suspended")]}), request, [], []),
            (ok({"bindings": [entry("binding_a", state=["active"])]}), request, [], []),
            # an entry that names no work is not of this one
            (ok({"bindings": [{"binding_id": "binding_a", "state": "active"}]}), request, [], []),
            (ok({"bindings": [entry("../no-binding")]}), request, None, None),
            (ok({"bindings": [entry("binding_a"), "binding_b"]}), request, None, None),
            # one binding listed twice, once tied and once not: it says nothing
            (ok({"bindings": [entry("binding_a"), entry("binding_a", profile="other")]}), request,
             None, None),
            (ok({"items": [], "more": False}), request, None, None),  # a page is not the complete list
            (ok(None), request, None, None),
            ({"schema_version": "1", "code": "SERVICE_UNAVAILABLE",
              "data": {"bindings": [entry("binding_a")]},
              "next": {"action": "retry_after"}}, request, None, None),
        )
        for envelope, asked, active, matching in rows:
            with self.subTest(envelope=envelope, asked=asked):
                reading = h2.read_work(envelope, asked)
                self.assertEqual(h2.lookup(reading.facts, "work.active"), active)
                self.assertEqual(h2.lookup(reading.facts, "work.matching"), matching)
                self.assertEqual(reading.code, envelope["code"])
        # The ties are the typed fields the list offers; none names a caller or a request.
        self.assertEqual([field for field, _ in h2.ATTRIBUTION], ["work_id", "profile", "created_at"])
        # An instant, to the nanosecond.
        self.assertEqual(h2.instant("1970-01-01T00:00:01.000000002Z"), 10**9 + 2)
        self.assertEqual(h2.instant("1970-01-01T00:00:00Z"), 0)
        self.assertEqual(h2.instant(after) - sent, 1)
        # The same instants as the standard library's calendar gives, a leap day and
        # the turns of a century included.
        for text in ("2000-02-29T23:59:59Z", "1900-03-01T00:00:00Z", "2026-11-23T10:00:00Z",
                     "1969-12-31T23:59:59Z", "2100-12-31T12:00:00Z", "2024-01-01T00:00:00Z"):
            moment = datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=datetime.timezone.utc)
            self.assertEqual(h2.instant(text), int(moment.timestamp()) * 10**9, text)
        for odd in ("2026-11-23", "2026-11-23T10:00:00.5", "2026-11-23T10:00:00.1234567890Z",
                    "2026-02-30T10:00:00Z", "2026-11-23T24:00:00Z", "2100-02-29T00:00:00Z",
                    "2026-11-23T10:60:00Z", "2026-11-23T10:00:60Z", "2026-00-01T00:00:00Z",
                    "2026-11-00T00:00:00Z", None, 5):
            self.assertIsNone(h2.instant(odd), odd)

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
                self.assertIn(row.states, (h2.SENDING, h2.TRACKED), row)
                self.assertEqual(row.to, "failed", row)
        self.assertNotIn("failed", h2.FOLLOW)
        # M07 W6c, and W7 for `pending_approval` and `reconciling`: a wait on the operation
        # of the request in progress that brought no answer, or was never started, leaves
        # the request uncertain: `failed` names it with the operation, whichever fault it was.
        self.assertEqual(h2.TRACKED, ("observing", "pending_approval", "reconciling"))
        for name in h2.TRACKED:
            for own in h2.FAULTS.values():
                reading = h2.Reading(own, "none", None, {"request": mine})
                self.assertEqual(h2.transition(sample_state(name), reading)[0].record(),
                                 dict(unsettled, state="failed", operation_id=SAMPLES["operation_id"]))
        # Only the step limit while reconciling keeps a request with the outcome of its own
        # uncertain answer; an answer of UNCERTAIN_CODES that ends its goal is kept so too.
        self.assertEqual((h2.KEPT, h2.UNCERTAIN_OUTCOME, h2.UNCERTAIN_CODES),
                         ({"unresolved": "outcome_unknown"}, "outcome_unknown", ("OUTCOME_UNKNOWN",)))
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
                                     (h2.STILL_OPEN, h2.ASKING, False),
                                     (h2.MISFIT, h2.ASKING, False),
                                     (h2.SHARED_FIND, h2.ASKING_BY_LIST, False)):
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
                self.assertIn(row.code, (h2.FOUND, h2.NEVER_RAN, h2.STILL_OPEN, h2.MISFIT,
                                         h2.SHARED_FIND), row)
            if set(row.states) & set(h2.ASKING):
                self.assertEqual(row.states, {h2.NEVER_RAN: h2.ASKING_BY_WAIT,
                                              h2.SHARED_FIND: h2.ASKING_BY_LIST}.get(row.code, h2.ASKING))
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
        allowed = {"argparse", "collections", "ctypes", "json", "os", "pathlib", "queue", "re",
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


class RecordedProcesses:
    """H2's Windows process calls as data (M07-W7-R03): each PID's process, as `table`
    gives it, and every call made, in `log`. A handle is `h<PID>`. A process with
    `stays` keeps running after it is terminated; `exits_after` ends it after that many
    waits."""

    def __init__(self, table, log=None):
        self.table, self.log = table, [] if log is None else log
        self.handles = {}

    def process(self, handle):
        return self.table[self.handles[handle]]

    def open(self, pid):
        self.log.append(("open", pid))
        entry = self.table.get(pid)
        if entry is None:
            return None
        if entry.get("open") == "error":
            raise OSError(5, "OpenProcess failed")
        handle = f"h{pid}"
        self.handles[handle] = pid
        return handle

    def close(self, handle):
        self.log.append(("close", handle))

    def created(self, handle):
        self.log.append(("created", handle))
        return self.process(handle)["created"]

    def facts(self, handle, pid):
        self.log.append(("facts", handle))
        entry = self.process(handle)
        if entry.get("facts") == "error":
            raise OSError(5, "GetProcessTimes failed")
        return h2.Facts(entry["parent"], entry["created"], entry["image"])

    @staticmethod
    def program(path):
        return PureWindowsPath(path)

    def wait(self, handle, seconds):
        self.log.append(("wait", handle, seconds))
        entry = self.process(handle)
        if entry.get("exits_after") is not None:
            entry["exits_after"] -= 1
            entry["running"] = entry["running"] and entry["exits_after"] > 0
        return not entry["running"]

    def terminate(self, handle):
        self.log.append(("terminate", handle))
        entry = self.process(handle)
        entry["running"] = entry["running"] and entry.get("stays", False)

    def exit_code(self, handle):
        self.log.append(("exit_code", handle))
        return self.process(handle).get("exit", 1)


class SpawnedChildTests(unittest.TestCase):
    """M07-W7-R03 as data, on every platform: the identity checks, the holding and the
    ending of the child Heimdall spawns on Windows, through RecordedProcesses."""

    HEIMDALL, CHILD = 400, 404
    PROGRAM = r"C:\fixture root\child.exe"

    def table(self, **child):
        return {self.HEIMDALL: {"created": 1000, "parent": 1, "image": None, "running": True},
                self.CHILD: dict({"created": 1001, "parent": self.HEIMDALL,
                                  "image": PureWindowsPath(self.PROGRAM.upper()), "running": True}, **child)}

    def test_the_identity_of_the_spawned_child_is_checked_in_order(self):
        started = h2.Started(self.HEIMDALL, 1000, [PureWindowsPath(self.PROGRAM)])
        child = h2.Facts(self.HEIMDALL, 1000, PureWindowsPath(self.PROGRAM.lower()))
        rows = (
            (child, None),
            (child._replace(created=5000), None),
            # another parent: not the child of the process this planner started
            (child._replace(parent=401), "its parent is not the process this planner started"),
            (child._replace(parent=None), "its parent is not the process this planner started"),
            # an older process with that parent's PID cannot be its child
            (child._replace(created=999), "it was created before the process this planner started"),
            (child._replace(created=None), "it was created before the process this planner started"),
            # another program: for example the runtime Heimdall may start on demand
            (child._replace(image=PureWindowsPath(r"C:\fixture root\heimdall.exe")),
             "it runs another program than the goal's"),
            (child._replace(image=None), "it runs another program than the goal's"),
            # each check in turn: the first that fails is the problem
            (h2.Facts(401, 999, None), "its parent is not the process this planner started"),
        )
        for facts, problem in rows:
            with self.subTest(facts=facts):
                self.assertEqual(h2.spawned_identity(facts, started), problem)
        # A batch script runs as the system directory's cmd.exe; anything else as itself.
        self.assertEqual(h2.child_programs(r"C:\r\t.CMD", r"C:\Windows"),
                         [r"C:\r\t.CMD", r"C:\Windows\System32\cmd.exe"])
        self.assertEqual(h2.child_programs(r"C:\r\t.bat", r"D:\W"), [r"C:\r\t.bat", r"D:\W\System32\cmd.exe"])
        for program, root in ((r"C:\r\t.exe", r"C:\Windows"), (r"C:\r\t.cmd", None), (r"C:\r\t.cmd", "Windows")):
            self.assertEqual(h2.child_programs(program, root), [program])

    def test_the_spawned_child_is_held_only_by_identity(self):
        programs = [self.PROGRAM]
        own = [("open", self.HEIMDALL), ("created", f"h{self.HEIMDALL}"), ("close", f"h{self.HEIMDALL}"),
               ("open", self.CHILD), ("facts", f"h{self.CHILD}")]
        child_closed = [("wait", f"h{self.CHILD}", 0), ("close", f"h{self.CHILD}")]
        refused = "its parent is not the process this planner started"
        # (the child's entry or None, the PID the record names; held, the problem, the calls)
        rows = (
            ({}, self.CHILD, True, None, own),
            # the record names the process this planner started: its own handle ends it
            ({}, self.HEIMDALL, False, None, []),
            ({}, "404", False, "the spawned record names no process", []),
            ({}, 0, False, "the spawned record names no process", []),
            # no process has the PID: the child has ended already
            (None, self.CHILD, False, None, own[:4]),
            ({"open": "error"}, self.CHILD, False, "the process the spawned record names could not be opened",
             own[:4]),
            # it fails a check while it runs: not held, not ended, its handle closed
            ({"parent": 401}, self.CHILD, False, refused, own + child_closed),
            ({"created": 999}, self.CHILD, False, "it was created before the process this planner started",
             own + child_closed),
            ({"image": PureWindowsPath(r"C:\Windows\System32\cmd.exe")}, self.CHILD, False,
             "it runs another program than the goal's", own + child_closed),
            # it fails a check because it has just exited: there is nothing to end
            ({"parent": 401, "running": False}, self.CHILD, False, None, own + child_closed),
            ({"facts": "error"}, self.CHILD, False, "the process the spawned record names could not be read",
             own + [("close", f"h{self.CHILD}")]),
        )
        for child, pid, held, problem, calls in rows:
            with self.subTest(child=child, pid=pid):
                table = self.table(**(child or {}))
                if child is None:
                    del table[self.CHILD]
                processes = RecordedProcesses(table)
                spawned, said = h2.hold_spawned(processes, pid, self.HEIMDALL, programs)
                self.assertEqual((spawned is not None, said), (held, problem))
                self.assertEqual(processes.log, calls)
                if held:  # held by the handle opened when the record was read, still open
                    self.assertEqual((spawned.pid, spawned.handle, spawned.ended), (self.CHILD, f"h{self.CHILD}", None))
                    self.assertNotIn(("close", f"h{self.CHILD}"), processes.log)
        self.assertEqual(h2.hold_spawned(None, self.CHILD, self.HEIMDALL, programs),
                         (None, "this platform cannot hold a process by its handle"))

    def test_the_held_child_is_ended_by_its_handle_once_and_within_the_bound(self):
        handle = f"h{self.CHILD}"
        # (the child's entry; what became of it, its exit code, the calls)
        rows = (
            ({"running": False, "exit": 0}, "exited", 0,
             [("wait", handle, 0), ("exit_code", handle), ("close", handle)]),
            ({"exit": 1}, "ended_by_handle", 1,
             [("wait", handle, 0), ("terminate", handle), ("wait", handle, 2.5), ("exit_code", handle),
              ("close", handle)]),
            ({"stays": True}, "not_ended", None,
             [("wait", handle, 0), ("terminate", handle), ("wait", handle, 2.5), ("close", handle)]),
        )
        for child, how, code, calls in rows:
            with self.subTest(child=child):
                processes = RecordedProcesses(self.table(**child))
                spawned = h2.Spawned(processes, self.CHILD, processes.open(self.CHILD))
                del processes.log[:]
                self.assertEqual(spawned.end(2.5), {"pid": self.CHILD, "ended": how, "exit_code": code})
                self.assertEqual(spawned.end(9), spawned.ended)  # once: a second end calls nothing
                self.assertEqual(processes.log, calls)
                self.assertIn(how, h2.ENDINGS)

    def test_the_child_is_ended_before_heimdall_and_whatever_became_of_heimdall(self):
        # On Windows Child.end ends the held child first, by its own handle, and then
        # Heimdall, which waits for it; a Heimdall that stays is terminated as before.
        log = []

        class Heimdall:
            def __init__(self, ends_with_child):
                self.stdin, self.stdout, self.stderr = io.BytesIO(), io.BytesIO(), io.BytesIO()
                self.returncode, self.ends_with_child = None, ends_with_child

            def wait(self, timeout=None):
                log.append(("heimdall wait",))
                child = processes.table[SpawnedChildTests.CHILD]
                if self.returncode is None and (child["running"] or not self.ends_with_child):
                    raise subprocess.TimeoutExpired("heimdall", timeout)
                if self.returncode is None:
                    self.returncode = 1
                return self.returncode

            def poll(self):
                return self.returncode

            def terminate(self):
                log.append(("heimdall terminate",))
                self.returncode = 1

            def kill(self):
                log.append(("heimdall kill",))
        handle = f"h{self.CHILD}"
        ended = [("wait", handle, 0), ("terminate", handle), ("wait", handle, 0.5),
                 ("exit_code", handle), ("close", handle)]
        for ends_with_child, calls in (
                (True, [("heimdall wait",), *ended, ("heimdall wait",)]),
                (False, [("heimdall wait",), *ended, ("heimdall wait",), ("heimdall terminate",),
                         ("heimdall wait",)])):
            with self.subTest(ends_with_child=ends_with_child):
                del log[:]
                processes = RecordedProcesses(self.table(), log)
                child = h2.Child(Heimdall(ends_with_child))
                child.spawned = h2.Spawned(processes, self.CHILD, processes.open(self.CHILD))
                del log[:]
                self.assertEqual(child.end(0.5), 1)
                self.assertEqual(log, calls)
                self.assertEqual(child.spawned.ended["ended"], "ended_by_handle")
        # A child that ended with its input closed is only waited on, never terminated.
        del log[:]
        processes = RecordedProcesses(self.table(exits_after=1), log)
        heimdall = Heimdall(True)
        heimdall.returncode = 0
        child = h2.Child(heimdall)
        child.spawned = h2.Spawned(processes, self.CHILD, processes.open(self.CHILD))
        del log[:]
        self.assertEqual(child.end(0.5), 0)
        self.assertEqual(log, [("heimdall wait",), ("wait", handle, 0), ("exit_code", handle), ("close", handle)])
        self.assertEqual(child.spawned.ended, {"pid": self.CHILD, "ended": "exited", "exit_code": 1})


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
        for kept in [self.root / "calls.jsonl", self.root / "received", *self.root.glob("count-*")]:
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

    def whole(self, argv, stub, stdout):
        """Run H2 as a whole against the stub, its summary into `stdout`, and return its
        exit status. On POSIX through `main`, the stub started through its interpreter
        line. Elsewhere (Windows) through `run`, the internal entry `main` calls, with
        the stub started through the interpreter: the same goals, exit code and summary."""
        posix = os.name == "posix"
        self.stub.write_text(f"#!{sys.executable} -IB\n{stub}" if posix else stub, encoding="utf-8")
        with patch.dict(os.environ, self.environment), contextlib.redirect_stdout(stdout):
            if posix:
                self.stub.chmod(0o700)
                return h2.main(argv)
            return h2.run(h2.parse_arguments(argv), [sys.executable, "-IB", str(self.stub)])

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
        planner = self.planner("never")
        record = h2.run_goal(planner, self.access("wider", pairs=["h3:deploy"]))
        self.assertFalse(record["success"])
        self.assertEqual(record["calls"], h2.MAX_STEPS)
        self.assertEqual(record["human_handoffs"], 1)
        # M07-W6-R01: the approval is still open at the step limit, so the request is
        # uncertain. `failed` names it with its operation, and it is remembered.
        request_id = self.calls()[0][7]
        self.assertEqual(record["final_state"], {"state": "failed", "code": "OUTCOME_UNKNOWN",
                                                 "operation_id": "op_fixture", "request_id": request_id})
        self.assertEqual(record["detail"], "the goal was not met within the step limit: "
                                           + repr(planner.state))
        self.assertEqual(len(record["transitions"]), h2.MAX_STEPS + 1)
        self.assertEqual(record["transitions"][-1]["code"], h2.BOUND)
        self.assertEqual(set(planner.requests), {request_id})

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
        # The wait's answer cannot be read as the operation's (M07 W6c): the accepted
        # request is uncertain, remembered with its operation, and never sent again.
        planner = self.planner("other-operation")
        record = h2.run_goal(planner, self.access(timeout_ms=1))
        self.assertFalse(record["success"])
        self.assertEqual(self.path(record), [("start", "ACCEPTED", "observe", "observing"),
                                             ("observing", h2.UNANSWERED, "none", "failed")])
        request_id = self.calls()[0][7]
        self.assertEqual(record["final_state"], {"state": "failed", "code": "OUTCOME_UNKNOWN",
                                                 "operation_id": "op_fixture", "request_id": request_id})
        self.assertEqual(record["detail"], "the answer is about another operation")
        self.assertEqual([(entry["fault"], entry["code"], entry["exit_code"])
                          for entry in record["requests_still_unknown"]], [("unreadable", "OK", 0)])
        self.assertEqual((record["calls"], list(planner.requests)), (2, [request_id]))

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
        # Ruled 2026-11-23 (fail closed): a request answered with a code that has no row
        # where it arrives, unknown or published, leaves the request uncertain. The goal
        # fails by no row, nothing is sent again, the request is remembered (with the
        # operation it named, if any) and the close observes it, and the run exits 1
        # whatever that observation finds.
        wait = ["operation", "wait", "op_fixture", "--timeout-ms", "20000"]
        inspect = ["inspect", "bindings"]
        found = {"outcome": "binding_found", "code": "ACCESS_READY", "exit_code": 0,
                 "observed": "operation", "bindings": ["binding_fixture"]}
        child = self.root / "child.sh"
        child.write_text("#!/bin/sh\nexit 0\n")
        # (the goal, the command it sends, its answer's code and exit status, the
        #  operation it named, the detail, the close's observation, the calls after it)
        cases = (
            # an unknown code to `access ensure`, naming no operation: observed through
            # the list of bindings, which names none for the work, so still unknown
            (self.access("novel"), ["access", "ensure"], "SOMETHING_NEW", 0, {},
             "unknown code SOMETHING_NEW",
             {"outcome": "still_unknown", "code": "OK", "exit_code": 0, "observed": "bindings",
              "listed": [], "candidates": []}, [inspect]),
            # a published code the table does not cover, naming its operation: observed by
            # that operation, which made a binding, held and released by the close
            (self.access("unsupported"), ["access", "ensure"], "UNSUPPORTED_CLIENT", 5,
             {"operation_id": "op_fixture"},
             "no transition from start for UNSUPPORTED_CLIENT with next change_client", found,
             [wait, ["access", "release", "binding_fixture"]]),
            # the same for a `run`, refused with an unknown code
            ({"goal": "run", "profile": "novel", "work_id": "work-1", "argv": [str(child)]}, ["run"],
             "SOMETHING_NEW", 1, {"operation_id": "op_fixture"}, "unknown code SOMETHING_NEW", found,
             [wait, ["access", "release", "binding_fixture"]]),
        )
        self.fails_closed(cases)

    def test_a_known_code_with_a_typed_field_present_but_invalid_fails_closed(self):
        # M07-W8-R03 (ruled 2026-11-23: fail closed): an answer whose code has a row, but
        # whose state refuses a typed field that is present and invalid, takes the same path
        # as one with no row. The goal fails by no row, the request is remembered
        # `still_unknown` with the envelope's valid `operation_id` where `next` names an
        # invalid one, the close observes it, and the run exits 1.
        wait = ["operation", "wait", "op_fixture", "--timeout-ms", "20000"]
        found = {"outcome": "binding_found", "code": "ACCESS_READY", "exit_code": 0,
                 "observed": "operation", "bindings": ["binding_fixture"]}
        released = [wait, ["access", "release", "binding_fixture"]]
        ensure = ["access", "ensure"]
        self.fails_closed((
            # `next.operation_id` is `op bad`; the envelope's own `op_fixture` is kept
            (self.access("bad-operation"), ensure, "ACCEPTED", 5, {"operation_id": "op_fixture"},
             "state observing was given an invalid operation_id", found, released),
            (self.access("bad-decision"), ensure, "APPROVAL_REQUIRED", 3, {"operation_id": "op_fixture"},
             "state pending_approval was given an invalid decision_ref", found, released),
            # it names no operation: observed through the list, which names none for the work
            (self.access("bad-binding"), ensure, "ACCESS_READY", 0, {},
             "state ready was given an invalid binding_id",
             {"outcome": "still_unknown", "code": "OK", "exit_code": 0, "observed": "bindings",
              "listed": [], "candidates": []}, [["inspect", "bindings"]]),
        ))

    def fails_closed(self, cases):
        """Run H2 as a whole for each case's one goal, a request answered with no row,
        and check that it failed closed: `cases` are (the goal, the command it sends, its
        answer's code and exit status, the operation it named, the goal's detail, the
        close's observation, the calls after the request)."""
        argv = ["--heimdall-bin", str(self.stub), "--scratch-root", str(self.root)]
        for goal, command, code, exit_code, named, detail, observed, after in cases:
            with self.subTest(goal=goal["goal"], code=code):
                self.fresh()
                stdout = io.StringIO()
                self.assertEqual(self.whole(argv + ["--goal", json.dumps(goal)], STUB, stdout), 1)
                summary = json.loads(stdout.getvalue())
                task, = summary["tasks"]
                calls = self.calls()
                # The goal fails, by no row, with exactly one call for the request.
                self.assertFalse(task["success"], task)
                self.assertEqual((task["final_state"], task["detail"]), ({"state": "failed", "code": code}, detail))
                self.assertEqual([step["by_table"] for step in task["transitions"]], [False])
                self.assertEqual(sum(call[:len(command)] == command for call in calls), 1)
                self.assertEqual(calls[0][:len(command)], command)
                request_id = calls[0][calls[0].index("--request-id") + 1]
                # The request is in the goal's uncertain list, and remembered.
                asked = {"call": h2.REQUESTS[h2.GOALS[goal["goal"]]["first"]], "profile": goal["profile"],
                         "work_id": "work-1"}
                own = dict(asked, request_id=request_id, code=code, exit_code=exit_code, detail=detail, **named)
                self.assertEqual(task["requests_still_unknown"], [own])
                self.assertEqual(task["held"], [])
                # The close observes it, once, before anything else, by the typed means it
                # named: its operation, else the list of bindings.
                self.assertEqual(calls[1:], after)
                attempts = summary["request_attempts"][request_id]
                self.assertEqual((attempts["call"], attempts["uncertain"]),
                                 (asked["call"], observed["outcome"] == "still_unknown"))
                self.assertEqual([attempt["outcome"] for attempt in attempts["attempts"]],
                                 ["still_unknown", observed["outcome"]])
                close = {key: value for key, value in attempts["attempts"][1].items() if key in observed}
                self.assertEqual(close, observed)
                self.assertEqual(summary["close"]["held"], [])

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
             {"state": "failed", "code": "OUTCOME_UNKNOWN", "operation_id": "op_fixture",
              "request_id": "(the request)"}),
            ("denied", 1, ("reconciling", "CAPABILITY_UNAVAILABLE", "none", "failed"),
             {"state": "failed", "code": "CAPABILITY_UNAVAILABLE"}),
        )
        for mode, observations, last, final in cases:
            with self.subTest(mode=mode):
                seen = len(self.calls())
                (self.root / "count-wait").unlink(missing_ok=True)  # the stub's count, per case
                record = h2.run_goal(self.planner(mode), self.access("uncertain"))
                if final.get("request_id"):  # the operation's own outcome is unknown: named (W7)
                    final = dict(final, request_id=self.calls()[seen][7])
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
                # M07 W6c: nothing is held, but the request is remembered with its
                # operation. A stop observes it once and sends nothing else; still
                # unfinished, it is still unknown, and the stop fails.
                request_id = calls[0][7]
                self.assertEqual(record["requests_outcome_unknown"], [{
                    "call": "access ensure", "profile": "uncertain", "work_id": "work-1",
                    "request_id": request_id, "code": "OUTCOME_UNKNOWN", "exit_code": 7,
                    "operation_id": "op_fixture"}])
                self.assertEqual(planner.requests, {request_id: {
                    "call": "access ensure", "profile": "uncertain", "work_id": "work-1",
                    "operation_id": "op_fixture"}})
                stopped = h2.run_goal(planner, {"goal": "stop"})
                self.assertFalse(stopped["success"])
                self.assertEqual(self.path(stopped), [
                    ("observing_request", h2.STILL_OPEN, "none", "failed")])
                self.assertEqual(self.calls()[seen + limit:], [wait])

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
                                                 "operation_id": "op_fixture",
                                                 "request_id": self.calls()[0][7]})
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
        # The launch's run record file stays while its child runs (on Windows, Heimdall
        # holds it open), and goes when the child has ended.
        self.assertEqual(len(list(self.root.glob("h2-run-*"))), 1)
        process = planner.child.process
        stopped = h2.run_goal(planner, {"goal": "stop"})
        self.assertEqual(list(self.root.glob("h2-run-*")), [])
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
        # M07-W3-R01, first probe: access is given, a later goal fails, then stop. The
        # later goal is refused by a row, and leaves nothing uncertain (an unlisted code
        # would leave its request for the stop to observe: W8c).
        planner = self.planner()
        self.assertTrue(h2.run_goal(planner, self.access())["success"])
        failed = h2.run_goal(planner, self.access(require_unattended=True))
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
                self.assertFalse(h2.run_goal(planner, self.access(require_unattended=True))["success"])
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
        misfit = ("exit 3 does not fit ACCESS_READY: its documented exit class is 0; "
                  "a probable product defect")
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
            # M07 W6c (ruled 2026-11-23): observed to have succeeded and to name its
            # binding, in the wrong exit class. The binding is held and released all the
            # same, still marked `inconsistent`, and the request is still unknown.
            ("ready-wrong-exit", {"timeout_ms": 1}, "close", "ACCEPTED", [], [wait, release],
             [dict(seen, outcome="still_unknown", code="ACCESS_READY", exit_code=3, bindings=[mine],
                   inconsistent=True, detail=misfit)], True),
            ("ready-wrong-exit", {"timeout_ms": 1}, "stop", "ACCEPTED", [], [wait, release],
             [dict(seen, outcome="still_unknown", code="ACCESS_READY", exit_code=3, bindings=[mine],
                   inconsistent=True, detail=misfit)], True),
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
                    outcome = "held" if "bindings" in later[0] and uncertain else later[0]["outcome"]
                    path = {"binding_found": [("observing_request", h2.FOUND, "none", "releasing"),
                                              ("releasing", "OK", "none", "stopped")],
                            "not_run": [("observing_request", h2.NEVER_RAN, "none", "stopped")],
                            "still_unknown": [("observing_request", h2.STILL_OPEN, "none", "failed")],
                            "held": [("observing_request", h2.MISFIT, "none", "releasing"),
                                     ("releasing", "OK", "none", "failed")]}
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
                        self.assertEqual(stopped["detail"],
                                         later[0].get("detail", "failed: OUTCOME_UNKNOWN"))
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

    def test_a_request_answered_with_its_operation_left_open_is_remembered_and_observed_later(self):
        # M07 W6c (ruled 2026-11-23), the two gaps beside a request that brought no
        # answer, closed by the same means: an `access ensure` answered `OUTCOME_UNKNOWN`
        # whose operation is still unfinished at the step limit (`unresolved`); and one
        # answered `ACCEPTED` whose wait then runs past its time limit or comes back
        # unreadable. Either may yet make a binding. The request is remembered with its
        # operation, never sent again, and observed by a later stop or the close before
        # any binding.
        mine, steps = "binding_fixture", h2.MAX_STEPS
        wait = ["operation", "wait", "op_fixture", "--timeout-ms", "20000"]
        release = ["access", "release", mine]
        asked = lambda profile: {"call": "access ensure", "profile": profile, "work_id": "work-1"}
        named = {"operation_id": "op_fixture"}
        unresolved = dict(named, outcome="outcome_unknown", code="OUTCOME_UNKNOWN", exit_code=7)
        late = dict(named, outcome="still_unknown", code=None, exit_code=None, fault="timed_out",
                    detail="a CLI call ran past its time limit", observed="operation")
        garbled = dict(late, exit_code=0, fault="unreadable",
                       detail="the CLI printed something that is not JSON")
        found = dict(named, outcome="binding_found", code="ACCESS_READY", exit_code=0,
                     observed="operation", bindings=[mine])
        still = dict(named, outcome="still_unknown", code="OK", exit_code=5, observed="operation")
        bound = ([("start", "OUTCOME_UNKNOWN", "reconcile", "reconciling")]
                 + [("reconciling", "OK", "observe", "reconciling")] * (steps - 1)
                 + [("reconciling", h2.BOUND, "none", "unresolved")])
        accepted = [("start", "ACCEPTED", "observe", "observing"),
                    ("observing", h2.UNANSWERED, "none", "failed")]
        # (the stub's mode, the profile and the goal's fields; the goal's path, and the
        #  list of its record that holds the request's own attempt; who observes next,
        #  the observation, and the calls after the goal)
        rows = (
            # Unfinished at the step limit: observed later to have made a binding, which
            # is released; or still unfinished, and still unknown.
            (f"unfinished-{steps - 1}", "uncertain", {}, bound, "requests_outcome_unknown", unresolved,
             "close", found, [wait, release]),
            (f"unfinished-{steps - 1}", "uncertain", {}, bound, "requests_outcome_unknown", unresolved,
             "stop", found, [wait, release]),
            ("never", "uncertain", {}, bound, "requests_outcome_unknown", unresolved,
             "close", still, [wait]),
            ("never", "uncertain", {}, bound, "requests_outcome_unknown", unresolved,
             "stop", still, [wait]),
            # Accepted, and its wait ran past its time limit, or could not be read.
            ("sleep:wait:normal", "covered", {"timeout_ms": 1}, accepted, "requests_still_unknown", late,
             "close", found, [wait, release]),
            ("sleep:wait:normal", "covered", {"timeout_ms": 1}, accepted, "requests_still_unknown", late,
             "stop", found, [wait, release]),
            ("sleep:wait:never", "covered", {"timeout_ms": 1}, accepted, "requests_still_unknown", late,
             "close", still, [wait]),
            ("sleep:wait:never", "covered", {"timeout_ms": 1}, accepted, "requests_still_unknown", late,
             "stop", still, [wait]),
            ("sleep:wait-garbled:normal", "covered", {"timeout_ms": 1}, accepted,
             "requests_still_unknown", garbled, "close", found, [wait, release]),
            ("sleep:wait-garbled:never", "covered", {"timeout_ms": 1}, accepted,
             "requests_still_unknown", garbled, "close", still, [wait]),
        )
        seen = self.watched(2.0, limited=(["operation", "wait"],))
        for mode, profile, fields, path, kept, own, by, observation, calls in rows:
            with self.subTest(mode=mode, profile=profile, by=by):
                self.fresh()
                del seen[:]
                planner = self.planner(mode)
                record = h2.run_goal(planner, self.access(profile, **fields))
                request_id, sent = seen[0][7], len(seen)
                uncertain = observation["outcome"] == "still_unknown"
                # The goal failed, and says so; its record names the request.
                self.assertFalse(record["success"])
                self.assertEqual(self.path(record), path)
                self.assertTrue(all(step["by_table"] for step in record["transitions"]))
                self.assertEqual(record["final_state"], dict(named, state="unresolved", code="OUTCOME_UNKNOWN")
                                 if path is bound else dict(named, state="failed", code="OUTCOME_UNKNOWN",
                                                            request_id=request_id))
                self.assertEqual(record["detail"], own.get("detail", "the goal was not met within the step "
                                                                     "limit: " + repr(planner.state)))
                attempt = {key: value for key, value in own.items() if key != "outcome"}
                for name in h2.REQUEST_RECORDED:
                    self.assertEqual(record[name], [dict(asked(profile), request_id=request_id, **attempt)]
                                     if name == kept else [], name)
                self.assertEqual((record["held"], planner.requests),
                                 ([], {request_id: dict(asked(profile), **named)}))
                if by == "close":
                    self.assertEqual(planner.close(), {"released": [mine] * (release in calls), "held": []})
                else:
                    stopped = h2.run_goal(planner, {"goal": "stop"})
                    self.assertEqual(self.path(stopped), [
                        ("observing_request", h2.STILL_OPEN, "none", "failed")] if uncertain else [
                        ("observing_request", h2.FOUND, "none", "releasing"),
                        ("releasing", "OK", "none", "stopped")])
                    self.assertEqual((stopped["success"], stopped["held"], stopped["calls"]),
                                     (not uncertain, [], len(calls)))
                    if uncertain:
                        self.assertEqual(stopped["final_state"], dict(
                            named, state="failed", code="OUTCOME_UNKNOWN", request_id=request_id))
                # The observation comes first, before any binding, and the request is
                # never sent again.
                self.assertEqual(seen[sent:], calls)
                self.assertEqual(sum(command[:2] == ["access", "ensure"] for command in seen), 1)
                self.assertEqual((planner.held, set(planner.requests)),
                                 ([], {request_id} if uncertain else set()))
                self.assertEqual(planner.by_request(), {request_id: dict(
                    asked(profile), uncertain=uncertain, attempts=[
                        dict(own, by="access"), dict(observation, by=by)])})
                self.assertEqual(planner.by_binding(), {})

    def left_open(self, rows, seconds=2.0):
        """Each row: a goal whose request was answered and whose operation the goal left
        open, then the close or a stop goal, which observes the request first. A row is
        (the stub's mode, the profile and the goal's fields; the goal's path, its final
        state with `request_id` True where the request is named, and the list of its
        record that holds the request's own attempt, that attempt; who observes next,
        the observation, and the calls after the goal, as the harness made them; a
        handoff the person abandons)."""
        mine = "binding_fixture"
        release = ["access", "release", mine]
        seen = self.watched(seconds, limited=(["operation", "wait"],))
        for (mode, profile, fields, path, final, kept, own, by, observation, calls,
             abandoned) in rows:
            with self.subTest(mode=mode, profile=profile, fields=fields, by=by):
                self.fresh()
                del seen[:]
                planner = self.planner(mode, handoff=(lambda report: False) if abandoned else None)
                record = h2.run_goal(planner, self.access(profile, **fields))
                request_id, sent = seen[0][7], len(seen)
                asked = {"call": "access ensure", "profile": profile, "work_id": "work-1"}
                uncertain = observation["outcome"] == "still_unknown"
                # The goal failed, and its record names the request, which is remembered
                # with the operation it left open, if any. Nothing more was sent.
                self.assertFalse(record["success"], record)
                self.assertEqual(self.path(record), path)
                # Every step came from a row, but a wait refused with a code no row acts on.
                self.assertEqual([step["by_table"] for step in record["transitions"]],
                                 [step["code"] in h2.known_codes() for step in record["transitions"]])
                self.assertEqual(record["final_state"], dict(final, **(
                    {"request_id": request_id} if final.get("request_id") else {})))
                attempt = {key: value for key, value in own.items() if key != "outcome"}
                for name in h2.REQUEST_RECORDED:
                    self.assertEqual(record[name], [dict(asked, request_id=request_id, **attempt)]
                                     if name == kept else [], name)
                named = {"operation_id": own["operation_id"]} if "operation_id" in own else {}
                self.assertEqual(planner.requests, {request_id: dict(asked, **named)})
                if by == "close":
                    planner.close()
                else:
                    stopped = h2.run_goal(planner, {"goal": "stop"})
                    self.assertEqual(stopped["success"], not uncertain, stopped)
                # The observation comes first, before any binding, and the request is
                # never sent again. A binding it shows is released.
                self.assertEqual(seen[sent:], calls)
                self.assertEqual(sum(command[:2] == ["access", "ensure"] for command in seen), 1)
                self.assertEqual((planner.held, set(planner.requests)),
                                 ([], {request_id} if uncertain else set()))
                self.assertEqual(planner.by_request(), {request_id: dict(
                    asked, uncertain=uncertain, attempts=[
                        dict(own, by="access"), dict(observation, by=by)])})
                self.assertEqual(planner.by_binding(), {})
                self.assertEqual(release in calls, mine in planner.ever_held)

    def test_an_answered_request_whose_operation_is_still_open_when_its_goal_stops_is_remembered(self):
        # M07-W6-R01, and W7 item 4 (an accepted request whose observation is answered by
        # Heimdall's own timeout: `operation wait` exits 5 with the operation still
        # going). The goal stops while the operation of its answered request is open: at
        # the step limit after `ACCEPTED` (`observing`) or an approval
        # (`pending_approval`), or at a wait refused for a transient reason. The
        # operation may yet make a binding. The request is remembered with its
        # operation, never sent again, and observed by the close or a later stop.
        steps = h2.MAX_STEPS
        wait = ["operation", "wait", "op_fixture", "--timeout-ms", "20000"]
        release = ["access", "release", "binding_fixture"]
        named = {"operation_id": "op_fixture"}
        bound = {"state": "failed", "code": "OUTCOME_UNKNOWN", "operation_id": "op_fixture",
                 "request_id": True}
        unfinished = dict(named, outcome="still_unknown", code="OK", exit_code=5, observed="operation")
        unavailable = dict(unfinished, code="SERVICE_UNAVAILABLE")
        found = dict(named, outcome="binding_found", code="ACCESS_READY", exit_code=0,
                     observed="operation", bindings=["binding_fixture"])
        accepted = ([("start", "ACCEPTED", "observe", "observing")]
                    + [("observing", "OK", "observe", "observing")] * (steps - 1)
                    + [("observing", h2.BOUND, "none", "failed")])
        approval = ([("start", "INTERACTION_REQUIRED", "interact", "pending_approval")]
                    + [("pending_approval", "OK", "observe", "pending_approval")] * (steps - 1)
                    + [("pending_approval", h2.BOUND, "none", "failed")])
        refused = lambda state: [("start", *{"observing": ("ACCEPTED", "observe"),
                                            "pending_approval": ("INTERACTION_REQUIRED", "interact")}[state],
                                  state), (state, "SERVICE_UNAVAILABLE", "retry_after", "failed")]
        # W8 item 3: a row ends the goal there, naming the request and its operation.
        transient = {"state": "failed", "code": "SERVICE_UNAVAILABLE", "operation_id": "op_fixture",
                     "request_id": True}
        late, pair = {"timeout_ms": 1}, {"pairs": ["h3:deploy"]}
        rows = (
            # `observing` at the step limit: every wait found it unfinished (exit 5). The
            # close then finds that it made a binding, or still unfinished.
            (f"unfinished-{steps - 1}", "covered", late, accepted, bound, "requests_still_unknown",
             unfinished, "close", found, [wait, release], False),
            (f"unfinished-{steps - 1}", "covered", late, accepted, bound, "requests_still_unknown",
             unfinished, "stop", found, [wait, release], False),
            ("never", "covered", late, accepted, bound, "requests_still_unknown",
             unfinished, "close", unfinished, [wait], False),
            # `pending_approval` at the step limit: the owner approves after the goal gave up.
            (f"unfinished-{steps - 1}", "covered", pair, approval, bound, "requests_still_unknown",
             unfinished, "close", found, [wait, release], False),
            ("never", "covered", pair, approval, bound, "requests_still_unknown",
             unfinished, "stop", unfinished, [wait], False),
            # A wait refused for a transient reason, in either state.
            ("sleep:wait-unavailable:normal", "covered", late, refused("observing"), transient,
             "requests_still_unknown", unavailable, "close", found, [wait, release], False),
            ("sleep:wait-unavailable:normal", "covered", pair, refused("pending_approval"), transient,
             "requests_still_unknown", unavailable, "stop", found, [wait, release], False),
        )
        self.left_open(rows)
        # Every code of a call refused for now has that row in each state that waits on the
        # operation of its request (codes.json: class 5, retryable, `retry_after`).
        published = json.loads((SOURCE.parents[3] / "schemas" / "public-api" / "codes.json").read_text(
            encoding="utf-8"))["codes"]
        self.assertEqual(h2.FOR_NOW, tuple(row["code"] for row in published if row["exit_code"] == 5
                                           and row["retryable"] and row["default_next_action"] == "retry_after"))
        mine = {"request_id": SAMPLES["request_id"], "operation_id": "op_other"}
        for name in h2.TRACKED:
            for code in h2.FOR_NOW:
                with self.subTest(state=name, code=code):
                    reading = h2.Reading(code, "retry_after", None, {"code": code, "request": mine})
                    after, row = h2.transition(sample_state(name), reading)
                    self.assertIsNotNone(row)
                    self.assertEqual(after.record(), {"state": "failed", "code": code,
                                                      "operation_id": SAMPLES["operation_id"],
                                                      "request_id": SAMPLES["request_id"]})
        # The published code is not called unknown (the re-check's side note).
        reading = h2.Reading("SERVICE_UNAVAILABLE", "retry_after", None, {})
        self.assertEqual(h2.no_row(h2.State("observing", operation_id="op_sample"), reading),
                         "no transition from observing for SERVICE_UNAVAILABLE with next retry_after")

    def test_the_other_requests_left_open_are_remembered_and_observed_later(self):
        # W7 item 5, the four cases the W6 workers left open, and an approval handoff the
        # person abandons: each is remembered and observed later like the others.
        wait = ["operation", "wait", "op_fixture", "--timeout-ms", "20000"]
        inspect = ["inspect", "bindings"]
        release = lambda binding="binding_fixture": ["access", "release", binding]
        named = {"operation_id": "op_fixture"}
        answered = {"outcome": "outcome_unknown", "code": "OUTCOME_UNKNOWN", "exit_code": 7}
        found = dict(named, outcome="binding_found", code="ACCESS_READY", exit_code=0,
                     observed="operation", bindings=["binding_fixture"])
        listed = {"outcome": "binding_found", "code": "OK", "exit_code": 0, "observed": "bindings",
                  "listed": ["binding_second"], "candidates": ["binding_second"],
                  "bindings": ["binding_second"]}
        silent = dict(named, outcome="still_unknown", code=None, exit_code=None, observed="operation",
                      fault="timed_out", detail="a CLI call ran past its time limit")
        wrong = lambda code, status, state: dict(
            named, outcome="still_unknown", code=code, exit_code=status, observed="operation",
            inconsistent=True, detail=f"exit {status} does not fit {state}: its documented exit "
                                      f"class is {0 if code == 'ACCESS_READY' else 5}; a probable product defect")
        failed = {"state": "failed", "code": "OUTCOME_UNKNOWN"}
        late, pair = {"timeout_ms": 1}, {"pairs": ["h3:deploy"]}
        accepted = ("start", "ACCEPTED", "observe", "observing")
        asked = ("start", "INTERACTION_REQUIRED", "interact", "pending_approval")
        rows = (
            # 1. `OUTCOME_UNKNOWN` whose `next` names no operation: remembered with none,
            # and observed through the list of bindings for its work; or with the
            # envelope's own operation, and observed by it.
            ("work:binding_second:active", "uncertain-unnamed", {},
             [("start", "OUTCOME_UNKNOWN", "reconcile", "failed")], failed, "requests_outcome_unknown",
             answered, "close", listed, [inspect, release("binding_second")], False),
            ("normal", "uncertain-unlinked", {},
             [("start", "OUTCOME_UNKNOWN", "reconcile", "failed")], dict(failed, **named),
             "requests_outcome_unknown", dict(answered, **named), "stop", found, [wait, release()], False),
            # 2. A wait with no answer while reconciling, and while an approval is pending.
            ("sleep:wait:normal", "uncertain", {},
             [("start", "OUTCOME_UNKNOWN", "reconcile", "reconciling"),
              ("reconciling", h2.UNANSWERED, "none", "failed")], dict(failed, request_id=True, **named),
             "requests_still_unknown", silent, "close", found, [wait, release()], False),
            ("sleep:wait:normal", "covered", pair, [asked, ("pending_approval", h2.UNANSWERED, "none", "failed")],
             dict(failed, request_id=True, **named), "requests_still_unknown", silent, "stop", found,
             [wait, release()], False),
            # 3. An observation inside the goal in the wrong exit class: an operation still
            # going answered with exit 0; one that succeeded and names its binding,
            # answered with exit 3 (the binding is held and released, and the request
            # stays unknown).
            ("sleep:wait-wrong:normal", "covered", late, [accepted, ("observing", h2.MISMATCH, "none",
                                                                     "inconsistent")],
             {"state": "inconsistent", "code": "OK", "exit_code": 0}, "requests_still_unknown",
             wrong("OK", 0, "an operation that is running"), "close", found, [wait, release()], False),
            ("ready-wrong-exit", "covered", late, [accepted, ("observing", h2.MISMATCH, "none", "inconsistent")],
             {"state": "inconsistent", "code": "ACCESS_READY", "exit_code": 3}, "requests_still_unknown",
             dict(wrong("ACCESS_READY", 3, "ACCESS_READY"), bindings=["binding_fixture"]), "close",
             wrong("ACCESS_READY", 3, "ACCESS_READY"), [wait, release()], False),
            # 4. An observed operation whose own code is `OUTCOME_UNKNOWN`.
            ("sleep:wait-unknown:normal", "covered", late,
             [accepted, ("observing", "OUTCOME_UNKNOWN", "none", "failed")],
             dict(failed, request_id=True, **named), "requests_still_unknown",
             dict(named, outcome="still_unknown", code="OUTCOME_UNKNOWN", exit_code=7, observed="operation"),
             "close", found, [wait, release()], False),
            # And an approval the person never came back from: its operation is open.
            ("normal", "covered", pair, [asked], {"state": "pending_approval", "decision_ref": "dec_fixture",
                                                  "operation_id": "op_fixture"},
             "requests_still_unknown", dict(named, outcome="still_unknown", code="INTERACTION_REQUIRED",
                                            exit_code=3),
             "close", found, [wait, release()], True),
        )
        self.left_open(rows)

    def test_an_expected_refusal_of_an_uncertain_outcome_is_never_met(self):
        # M07-W6-R03 (the re-check's E2): `OUTCOME_UNKNOWN` naming no operation, with a
        # contradictory effect `none`, met a goal that expected that code, and the run
        # exited 0. An uncertain outcome is never a refusal a goal can expect: the goal
        # fails, and the request is remembered (W7 item 5) and observed through the list
        # of bindings for its work.
        found = "binding_second"
        asked = {"call": "access ensure", "profile": "uncertain-none", "work_id": "work-1"}
        for mode, later, released in ((f"work:{found}:active", "binding_found", [found]),
                                      (f"work:{found}:none", "still_unknown", [])):
            with self.subTest(mode=mode):
                self.fresh()
                planner = self.planner(mode)
                record = h2.run_goal(planner, self.access("uncertain-none", expect_refusal="OUTCOME_UNKNOWN"))
                request_id = self.calls()[0][7]
                self.assertFalse(record["success"], record)
                self.assertEqual(self.path(record), [("start", "OUTCOME_UNKNOWN", "reconcile", "failed")])
                self.assertEqual((record["final_state"], record["detail"]),
                                 ({"state": "failed", "code": "OUTCOME_UNKNOWN"}, "failed: OUTCOME_UNKNOWN"))
                self.assertEqual(record["requests_outcome_unknown"], [dict(
                    asked, request_id=request_id, code="OUTCOME_UNKNOWN", exit_code=7)])
                self.assertEqual(planner.requests, {request_id: asked})
                self.assertEqual(planner.close(), {"released": released, "held": []})
                self.assertEqual([attempt["outcome"] for attempt in planner.by_request()[request_id]["attempts"]],
                                 ["outcome_unknown", later])
                self.assertEqual(sum(call[:2] == ["access", "ensure"] for call in self.calls()), 1)
        # Expecting another refusal is as before: met only by that refusal with effect none.
        record = h2.run_goal(self.planner(), self.access(require_unattended=True,
                                                          expect_refusal="CAPABILITY_UNAVAILABLE"))
        self.assertTrue(record["success"], record)

    def test_the_run_fails_while_a_request_or_a_release_is_still_uncertain(self):
        # M07-W6-R03, generally: whatever the goals' own results, the run exits 1 while a
        # request or a release is still uncertain.
        planner = self.planner()
        met, closed = [{"success": True}], {"released": [], "held": []}
        self.assertEqual(h2.exit_status(met, closed, planner), 0)
        planner.requests["request-open"] = {"call": "access ensure", "profile": "covered", "work_id": "work-1"}
        self.assertEqual(h2.exit_status(met, closed, planner), 1)
        planner.requests.clear()
        planner.uncertain["binding_open"] = {"request_id": None}
        self.assertEqual(h2.exit_status(met, closed, planner), 1)
        planner.uncertain.clear()
        self.assertEqual(h2.exit_status([{"success": False}], closed, planner), 1)
        self.assertEqual(h2.exit_status(met, {"released": [], "held": ["binding_x"]}, planner), 1)

    def test_the_run_fails_while_the_child_heimdall_spawned_could_not_be_shown_ended(self):
        # M07-W7-R03 (M07-W8-R04): where the close could not show the held child ended, the
        # run exits 1 whatever else it found; any other ending of it fails nothing.
        planner = self.planner()
        for ended, status in (("not_ended", 1), ("exited", 0), ("ended_by_handle", 0), (None, 0)):
            with self.subTest(ended=ended):
                closing = {"released": [], "held": []}
                if ended is not None:
                    closing["spawned_child"] = {"pid": 4242, "ended": ended,
                                                "exit_code": None if ended == "not_ended" else 1}
                self.assertEqual(h2.exit_status([{"success": True}], closing, planner), status)

    def test_requests_for_one_work_and_profile_are_observed_together_and_each_binding_is_credited_once(self):
        # M07-W6-R02 (the re-check's A15 and A16): two requests for the same work and
        # profile bring no answer and name no operation. One read of the list of bindings
        # observes both, the newest first, and each binding is credited to one request at
        # most: the newest has the fewest candidates. M07-W7-R04: a binding made after the
        # newer request was sent can be the older one's too, which was sent before it was
        # made. Ruled 2026-11-23 (the strict reading): a read in which any binding is a
        # candidate of two requests credits no request. The newer request's one candidate,
        # shared, is released (it is one of H2's own requests' either way); every request
        # of the read stays uncertain, each naming those it shares a candidate with; and
        # nothing else is held.
        one, two, late = "binding_second", "binding_many_7", "binding_many_late"
        inspect = ["inspect", "bindings"]
        # {request: (its first observation's outcome, `listed`, its candidates in that
        #  read, the bindings it gave, the requests it names in `shared_with`)}
        rows = (
            # A15: `one` made between the two sendings, `two` after both. `two` is a
            # candidate of both requests, so the read is ambiguous: neither is credited.
            # `two` is released; `one`, the older request's other candidate, is not held
            # (with two candidates and no credit, it is tied to no request).
            (f"work:{one}/made-1,{two}/made-2:active", "close",
             {1: ("still_unknown", [one, two], [one, two], [], [2]),
              2: ("still_unknown", [one, two], [two], [two], [1])}),
            (f"work:{one}/made-1,{two}/made-2:active", "stop",
             {1: ("still_unknown", [one, two], [one, two], [], [2]),
              2: ("still_unknown", [one, two], [two], [two], [1])}),
            # A16, and the reviewer's `made-2` case (M07-W7-R04's own): one binding, made
            # after the newer request was sent, a candidate of both. It is released, once,
            # and both requests stay uncertain, each naming the other.
            (f"work:{two}/made-2:active", "close",
             {1: ("still_unknown", [two], [two], [], [2]), 2: ("still_unknown", [two], [two], [two], [1])}),
            (f"work:{late}/made-2:active", "close",
             {1: ("still_unknown", [late], [late], [], [2]),
              2: ("still_unknown", [late], [late], [late], [1])}),
            (f"work:{late}/made-2:active", "stop",
             {1: ("still_unknown", [late], [late], [], [2]),
              2: ("still_unknown", [late], [late], [late], [1])}),
            # The `made-1` control: made before the newer request was sent, the binding is a
            # candidate of the older one only. Nothing is ambiguous: it is credited to the
            # older one and released, and the newer one, with no candidate, stays uncertain.
            (f"work:{late}/made-1:active", "close",
             {1: ("binding_found", [late], [late], [late], []), 2: ("still_unknown", [late], [], [], [])}),
        )
        seen = self.watched(2.0, limited=(["access", "ensure"],))
        for mode, by, outcomes in rows:
            with self.subTest(mode=mode, by=by):
                self.fresh()
                del seen[:]
                planner = self.planner(mode)
                for _ in range(2):
                    self.assertFalse(h2.run_goal(planner, self.access("silent"))["success"])
                requests = [command[7] for command in seen[:2]]
                self.assertEqual(list(planner.requests), requests)
                if by == "close":
                    closing = planner.close()
                else:
                    stopped = h2.run_goal(planner, {"goal": "stop"})
                    closing = planner.close()
                    self.assertEqual(stopped["success"], all(
                        outcome == "binding_found" for outcome, *_ in outcomes.values()))
                released = {binding for _, _, _, given, _ in outcomes.values() for binding in given}
                # One read for both, then one release for each binding credited.
                after = seen[2:]
                self.assertEqual(after[0], inspect)
                self.assertEqual(sorted(command[2] for command in after if command[:2] == ["access", "release"]),
                                 sorted(released))
                self.assertEqual(after.count(inspect), 1 + (by == "stop") * (
                    "still_unknown" in [outcome for outcome, *_ in outcomes.values()]))
                self.assertEqual(planner.held, [])
                self.assertEqual(set(planner.ever_held), released)
                self.assertEqual(set(planner.requests), {requests[index - 1] for index, (outcome, *_)
                                                         in outcomes.items() if outcome == "still_unknown"})
                for index, (outcome, listed, candidates, given, shared) in outcomes.items():
                    first = planner.by_request()[requests[index - 1]]["attempts"][1]
                    self.assertEqual((first["outcome"], first["listed"], first.get("bindings", [])),
                                     (outcome, listed, given), index)
                    self.assertEqual(first["candidates"], candidates, index)
                    self.assertEqual(first.get("shared_with", []), [requests[other - 1] for other in shared],
                                     index)
                # Whatever was credited, the run fails while a request is uncertain.
                if planner.requests:
                    self.assertEqual(h2.exit_status([{"success": True}], closing, planner), 1)
                if by == "close":
                    self.assertEqual(sorted(closing["released"]), sorted(released))
                # A binding no request was credited with, and that is no shared candidate,
                # is never released: A15's `one`.
                self.assertNotIn(["access", "release", one], after)
                # ...and it is not silent: the summary names it, with the requests it was a
                # candidate of, and the run fails (ruled 2026-11-23).
                left = [f"unattributed binding left active: {one} (candidates: {requests[0]})"] \
                    if one in outcomes[1][2] else []
                self.assertEqual(planner.left_active(), left)
                if left:
                    self.assertEqual(h2.exit_status([{"success": True}], closing, planner), 1)
        # A request that named an operation is observed before those observed through the
        # list: the binding its operation names is its own, and never another's candidate.
        planner = self.planner()
        planner.requests.update({"request-listed": {"call": "access ensure", "profile": "p", "work_id": "w"},
                                 "request-waited": {"call": "access ensure", "profile": "p", "work_id": "w",
                                                    "operation_id": "op_sample"}})
        self.assertEqual(planner.open_requests(), ["request-waited", "request-listed"])

    def test_what_a_read_found_a_request_can_have_made_stays_its_own_in_every_later_read(self):
        # M07-W8-R01 (ruled 2026-11-23): every binding a read of the list found that a
        # remembered request can have made counts as that request's in every later read,
        # whether or not the list still names it `active`. The list is `live` here: a
        # binding H2 released is listed `released` from then on, as Heimdall lists it. So
        # a request an earlier read could not credit is never credited later, and the
        # binding H2 never held stays active and is named in the summary.
        one, two = "binding_second", "binding_many_7"
        inspect = ["inspect", "bindings"]
        # (the mode, how many silent requests, {request: its observations after its own
        #  attempt, each (by, outcome, `listed`, candidates, the bindings it gave, the
        #  requests it names in `shared_with`)}, the calls after the requests, and
        #  {binding left active: the requests it was a candidate of})
        rows = (
            # A15, a stop and then the close (the reviewer's case): `two` is shared, held
            # and released by the stop; the close's read lists it `released`. R1 can have
            # made it, so R1's one candidate left, `one`, is not credited or released.
            (f"work:{one}/made-1,{two}/made-2:live", 2,
             {1: [("stop", "still_unknown", [one, two], [one, two], [], [2]),
                  ("close", "still_unknown", [one], [one], [], [2])],
              2: [("stop", "still_unknown", [one, two], [two], [two], [1]),
                  ("close", "still_unknown", [one], [], [], [1])]},
             [inspect, ["access", "release", two], inspect], {one: [1]}),
            # SEVERAL, with no shared binding: one request with two candidates, one of
            # which is gone from the list by the close (`@1`: listed in the first read
            # only). The request can have made either, so the one left is not credited.
            (f"work:{one}/made-1@1,{two}/made-1:live", 1,
             {1: [("stop", "still_unknown", [one, two], [one, two], [], []),
                  ("close", "still_unknown", [two], [two], [], [])]},
             [inspect, inspect], {one: [1], two: [1]}),
        )
        seen = self.watched(2.0, limited=(["access", "ensure"],))
        for mode, count, outcomes, after, left in rows:
            with self.subTest(mode=mode):
                self.fresh()
                del seen[:]
                planner = self.planner(mode)
                for _ in range(count):
                    self.assertFalse(h2.run_goal(planner, self.access("silent"))["success"])
                requests = [command[7] for command in seen[:count]]
                self.assertFalse(h2.run_goal(planner, {"goal": "stop"})["success"])
                closing = planner.close()
                self.assertEqual(seen[count:], after)
                self.assertEqual(closing, {"released": [], "held": []})
                self.assertEqual(list(planner.requests), requests)
                for index, observations in outcomes.items():
                    attempts = planner.by_request()[requests[index - 1]]["attempts"]
                    self.assertEqual(
                        [(attempt["by"], attempt["outcome"], attempt["listed"], attempt["candidates"],
                          attempt.get("bindings", []), attempt.get("shared_with", []))
                         for attempt in attempts[1:]],
                        [(by, outcome, listed, candidates, given, [requests[other - 1] for other in shared])
                         for by, outcome, listed, candidates, given, shared in observations], index)
                self.assertEqual(planner.left_active(), [
                    f"unattributed binding left active: {binding} "
                    f"(candidates: {', '.join(requests[index - 1] for index in indices)})"
                    for binding, indices in left.items()])
                self.assertEqual(h2.exit_status([{"success": True}], closing, planner), 1)

    def test_a_request_that_named_an_operation_counts_in_the_read_of_the_list(self):
        # M07-W8-R02 (ruled 2026-11-23): a remembered request of the same work and profile
        # that named an operation, still uncertain once the stop has waited on it (here
        # the wait is refused for now), counts in the read of the list: what it can have
        # made goes into `could`, and it is never credited from the list. The list names
        # one binding, made after both requests were sent: either can have made it, so
        # the silent request is not credited. The binding is held and released (it is one
        # of H2's own requests' either way), and the silent request stays uncertain, in
        # the close too, after the operation has said it made another binding.
        binding = "binding_many_7"
        wait = ["operation", "wait", "op_fixture", "--timeout-ms", "20000"]
        inspect = ["inspect", "bindings"]
        seen = self.watched()
        planner = self.planner(f"sleep:wait-unavailable:work:{binding}:active")
        now = time.time_ns()
        asked = {"call": "access ensure", "profile": "covered", "work_id": "work-1"}
        # as `remember` leaves two requests: the older named an operation, the newer none
        planner.requests.update({"request-op": dict(asked, operation_id="op_fixture"),
                                 "request-silent": dict(asked)})
        planner.sent_at.update({"request-op": now - 20 * 10**9, "request-silent": now - 10 * 10**9})
        self.assertFalse(h2.run_goal(planner, {"goal": "stop"})["success"])
        closing = planner.close()
        self.assertEqual(seen, [wait, inspect, ["access", "release", binding],
                                wait, inspect, ["access", "release", "binding_fixture"]])
        self.assertEqual(closing, {"released": ["binding_fixture"], "held": []})
        observations = {request_id: [(attempt["by"], attempt["outcome"], attempt["code"],
                                      attempt.get("candidates"), attempt.get("bindings", []),
                                      attempt.get("shared_with", []))
                                     for attempt in entry["attempts"]]
                        for request_id, entry in planner.by_request().items()}
        self.assertEqual(observations, {
            "request-op": [("stop", "still_unknown", "SERVICE_UNAVAILABLE", None, [], []),
                           ("close", "binding_found", "ACCESS_READY", None, ["binding_fixture"], [])],
            "request-silent": [("stop", "still_unknown", "OK", [binding], [binding], ["request-op"]),
                               ("close", "still_unknown", "OK", [], [], [])]})
        self.assertEqual(list(planner.requests), ["request-silent"])
        self.assertEqual(planner.left_active(), [])
        self.assertEqual(h2.exit_status([{"success": True}], closing, planner), 1)

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
        # What the list showed: the bindings it names for the work, `active`, and those
        # of them that can be the request's own.
        shown = lambda listed, candidates: dict(ok, listed=listed, candidates=candidates)
        nothing = dict(shown([], []), outcome="still_unknown")
        rows = (
            # The list names one binding for that work, `active`, of the request's
            # profile, made after the request was sent, that H2 was never given: it is a
            # binding to release, and it is released.
            ("silent", f"{found}:active", "close", late,
             dict(shown([found], [found]), outcome="binding_found", bindings=[found]), [found]),
            ("silent", f"{found}:active", "stop", late,
             dict(shown([found], [found]), outcome="binding_found", bindings=[found]), [found]),
            # M07 W6c (ruled 2026-11-23): two can be the request's. Which is not known,
            # so neither is released, and the request is still unknown.
            ("silent", f"{found},{other}:active", "close", late,
             dict(shown([found, other], [found, other]), outcome="still_unknown"), []),
            ("silent", f"{found},{other}:active", "stop", late,
             dict(shown([found, other], [found, other]), outcome="still_unknown"), []),
            # Another caller's binding, or another request's, is left alone: the same
            # work with another profile; made before the request was sent; with no
            # creation time to tie it to the request.
            ("silent", f"{found}/other:active", "close", late,
             dict(shown([found], []), outcome="still_unknown"), []),
            ("silent", f"{found}/other:active", "stop", late,
             dict(shown([found], []), outcome="still_unknown"), []),
            ("silent", f"{found}/before:active", "close", late,
             dict(shown([found], []), outcome="still_unknown"), []),
            ("silent", f"{found}/undated:active", "close", late,
             dict(shown([found], []), outcome="still_unknown"), []),
            # Beside another caller's, the one that can be the request's is released.
            ("silent", f"{found},{other}/other:active", "close", late,
             dict(shown([found, other], [found]), outcome="binding_found", bindings=[found]), [found]),
            ("silent", f"{other}/before,{found}:active", "stop", late,
             dict(shown([other, found], [found]), outcome="binding_found", bindings=[found]), [found]),
            # The answer could not be read: the same, with the exit status it had.
            ("garbled", f"{found}:active", "close", garbled,
             dict(shown([found], [found]), outcome="binding_found", bindings=[found]), [found]),
            # The list names no binding for that work, or none that is `active`: that is
            # no evidence that the request never ran. Still unknown, and nothing is sent.
            ("silent", f"{found}:none", "close", late, nothing, []),
            ("silent", f"{found}:none", "stop", late, nothing, []),
            ("silent", f"{found}:released", "close", late, nothing, []),
            ("silent", f"{found}:odd", "close", late, nothing, []),
            # The list could not be read: still unknown.
            ("silent", f"{found}:unknown", "close", late,
             {"outcome": "still_unknown", "code": "SERVICE_UNAVAILABLE", "exit_code": 5,
              "observed": "bindings"}, []),
            # M07 W6c (ruled 2026-11-23): it names the request's binding in the wrong
            # exit class. The binding is held and released all the same, still marked
            # `inconsistent`, and the request is still unknown.
            ("silent", f"{found}:wrong-exit", "close", late,
             dict(shown([found], [found]), outcome="still_unknown", exit_code=4, bindings=[found],
                  inconsistent=True, detail=defect), [found]),
            ("silent", f"{found},{other}:wrong-exit", "close", late,
             dict(shown([found, other], [found, other]), outcome="still_unknown", exit_code=4,
                  inconsistent=True, detail=defect), []),
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
             "observed": "bindings", "listed": [mine], "candidates": []}]))
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
             dict(ok, outcome="binding_found", listed=[found], candidates=[found], bindings=[found]),
             [found]),
            (f"sleep:run:work:{found}:none", "covered", 0.5, late,
             dict(ok, outcome="still_unknown", listed=[], candidates=[]), []),
            # It ended by itself, and what it left is neither a run record nor one
            # envelope: uncertain in the same way.
            (f"work:{found}:none", "garbled", h2.LAUNCH_SECONDS, garbled,
             dict(ok, outcome="still_unknown", listed=[], candidates=[]), []),
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

    def test_a_windows_launch_is_read_by_its_spawned_record(self):
        # W7 item 6: on Windows Heimdall writes `launching` with its own PID, spawns the
        # child, writes `spawned` with the child's, and waits for it. That pair is a
        # launch there, and `launching` alone is one on Unix (LAUNCHED). Either platform's
        # records on the other are not, and the child is ended. Stub-covered here; the
        # real Windows sequence is A32's task 5 in tests/e2e/harness_m07.rs.
        child = [str(self.stub), "fixture-argument"]
        self.assertEqual(h2.LAUNCHED, {"posix": ("launching",), "nt": ("launching", "spawned")})
        for platform, mode in (("nt", "spawned"), ("posix", "normal"), ("posix", "spawned"), ("nt", "normal")):
            # What the stub writes: on Windows it always writes `spawned`, as Heimdall does.
            written = ("launching", "spawned") if mode == "spawned" or os.name == "nt" else ("launching",)
            launched = written == h2.LAUNCHED[platform]
            with self.subTest(platform=platform, mode=mode), patch.object(h2, "SPAWNED_SECONDS", 0.3):
                self.fresh()
                planner = self.planner(mode)
                planner.platform = platform
                self.assertTrue(h2.run_goal(planner, self.access())["success"])
                record = h2.run_goal(planner, {"goal": "run", "profile": "covered", "work_id": "work-1",
                                               "argv": child})
                self.assertEqual(record["success"], launched, record)
                if launched:
                    self.assertEqual(record["final_state"]["pid"], planner.child.process.pid)
                    stopped = h2.run_goal(planner, {"goal": "stop"})
                    self.assertEqual((stopped["success"], stopped["child_exit_code"]), (True, 0))
                else:
                    self.assertEqual(record["detail"], "the run records do not tell of a launch on "
                                                       "this platform: " + ", ".join(written))
                    self.assertIsNone(planner.child)
                    self.assertEqual(planner.close(), {"released": ["binding_fixture"], "held": []})
                self.assertEqual(list(self.root.glob("h2-run-*")), [])
        # The child may be the in-box OpenSSH client itself on Windows, and nothing else
        # outside the scratch root: never on another platform, never where it is no file.
        self.assertEqual(h2.in_box_ssh("C:\\Windows"), PureWindowsPath("c:/windows/system32/openssh/SSH.EXE"))
        for odd in ("Windows", "", None, "\\Windows"):
            self.assertIsNone(h2.in_box_ssh(odd), odd)
        # A system directory that exists on no host (a fresh random name), so the case never
        # depends on the machine's own System32: on a real Windows host the in-box client is a
        # file there (PC job 46 found the earlier fixed C:\\Windows accepted).
        absent = "C:\\heimdall-h2-absent-" + uuid.uuid4().hex
        for platform in ("nt", "posix"):
            planner = self.planner(environment=dict(self.environment, SystemRoot=absent))
            planner.platform = platform
            record = h2.run_goal(planner, {"goal": "run", "profile": "covered", "work_id": "work-5",
                                           "argv": [str(h2.in_box_ssh(absent)), "-T"]})
            self.assertEqual((record["success"], record["calls"]), (False, 0))
            self.assertEqual(record["detail"], "the child executable is not a file inside the scratch "
                                               "root, nor the in-box OpenSSH client")

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

    def spawned_child_stop(self, child, processes, gone, cleanup):
        """M07-W7-R03: a run goal under the stub's `spawn-child` mode (the launch as
        Heimdall makes it on Windows: Heimdall spawns the child and waits for it), whose
        child `child` ignores the end of its input, then a stop. `processes` are the
        process calls the planner holds the child with (None: its own), `gone(pid)`
        waits a bounded time and says whether the child has ended, and `cleanup(pid)`
        ends it where it has not. Returns the run and stop records and the child's PID."""
        planner = self.planner("spawn-child")
        planner.platform = "nt"
        if processes is not None:
            planner.processes = processes
        goal = {"goal": "run", "profile": "covered", "work_id": "work-6", "argv": child}
        running = h2.run_goal(planner, goal)
        pid = int((self.root / "spawned-pid").read_text())
        self.addCleanup(cleanup, pid)
        self.assertTrue(running["success"], running)
        launch = self.calls()[0]
        self.assertEqual(launch[9:], ["--", *child])
        heimdall = planner.child.process
        with patch.object(h2, "CHILD_END_SECONDS", 0.5):
            stopped = h2.run_goal(planner, {"goal": "stop"})
        # The child is gone once the stop has ended it, and so is Heimdall.
        self.assertTrue(gone(pid), "the child Heimdall spawned outlived the stop")
        self.assertIsNotNone(heimdall.returncode)
        self.assertEqual(running["spawned_child"], {"pid": pid, "held": True})
        self.assertEqual(stopped["spawned_child"]["pid"], pid)
        self.assertEqual(stopped["spawned_child"]["ended"], "ended_by_handle")
        # It was ended, so the stop fails as for any child that stays (exit status != 0).
        self.assertFalse(stopped["success"])
        self.assertNotEqual(stopped["child_exit_code"], 0)
        self.assertEqual(planner.close(), {"released": [], "held": []})
        return running, stopped, pid

    @unittest.skipUnless(os.name == "posix", "the POSIX stand-in for the Windows process calls")
    def test_the_child_heimdall_spawned_is_ended_by_its_own_handle_through_a_posix_stand_in(self):
        # M07-W7-R03 on POSIX: the platform's records are Windows', and the planner's
        # process calls are a stand-in that reads the real parent with `ps` and ends a
        # process by its exact PID. The child `exec`s `sleep`, which ignores its input.
        child = self.root / "stubborn"
        child.write_text("#!/bin/sh\nexec /bin/sleep 30\n", encoding="utf-8")
        child.chmod(0o700)

        class PosixProcesses:
            """A handle is the PID itself; the child's program is the goal's."""
            def open(self, pid):
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    return None
                return pid

            def close(self, handle):
                pass

            def created(self, handle):
                return 0

            def facts(self, handle, pid):
                parent = subprocess.run(["/bin/ps", "-o", "ppid=", "-p", str(pid)], capture_output=True,
                                        text=True, timeout=10).stdout.strip()
                return h2.Facts(int(parent) if parent.isdigit() else None, 1, str(child))

            @staticmethod
            def program(path):
                return str(path)

            def wait(self, handle, seconds):
                deadline = time.monotonic() + seconds
                while True:
                    try:
                        os.kill(handle, 0)
                    except ProcessLookupError:
                        return True
                    if time.monotonic() >= deadline:
                        return False
                    time.sleep(0.02)

            def terminate(self, handle):
                os.kill(handle, 9)

            def exit_code(self, handle):
                return 1

        def cleanup(pid):  # only where the stop left it: this test started it, by its exact PID
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, 9)
        self.spawned_child_stop([str(child)], PosixProcesses(), lambda pid: PosixProcesses().wait(pid, 5),
                                cleanup)

    @unittest.skipUnless(os.name == "nt", "requires Windows")
    def test_windows_the_child_heimdall_spawned_is_ended_by_its_own_handle(self):
        # M07-W7-R03 on Windows, with the planner's own kernel32 calls: the child is a
        # batch script, run by the system directory's cmd.exe as Rust's std runs one,
        # that loops without reading its input. The test holds a handle of its own to
        # the child, so the PID it waits on cannot name another process.
        import ctypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.OpenProcess.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
        kernel.WaitForSingleObject.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
        kernel.WaitForSingleObject.restype = ctypes.c_uint32
        kernel.TerminateProcess.argtypes = (ctypes.c_void_p, ctypes.c_uint)
        kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
        child = self.root / "stubborn.cmd"
        child.write_text("@echo off\r\n:again\r\ngoto again\r\n", encoding="utf-8")
        handles = {}

        def held(pid):
            if pid not in handles:  # SYNCHRONIZE | PROCESS_TERMINATE
                handles[pid] = kernel.OpenProcess(0x00100000 | 0x0001, False, pid)
            return handles[pid]

        def gone(pid):
            return held(pid) is not None and kernel.WaitForSingleObject(held(pid), 5000) == 0

        def cleanup(pid):  # only where the stop left it, by the test's own handle
            if handles.get(pid) is not None:
                if kernel.WaitForSingleObject(handles[pid], 0) != 0:
                    kernel.TerminateProcess(handles[pid], 1)
                    kernel.WaitForSingleObject(handles[pid], 5000)
                kernel.CloseHandle(handles[pid])
        planner_processes = None  # the planner's own: h2.WindowsProcesses
        original = h2.Planner.launch

        def launch(planner, *arguments):  # the test's handle, opened as soon as the child exists
            reading = original(planner, *arguments)
            held(int((self.root / "spawned-pid").read_text()))
            return reading
        with patch.object(h2.Planner, "launch", launch):
            self.spawned_child_stop([str(child)], planner_processes, gone, cleanup)

    def launch_held_as_data(self, mode, **child):
        """A `run` goal under the stub's `spawn-child` or `spawn-child-mute` mode, read as
        on Windows, with the planner's process calls as data (RecordedProcesses). The PID
        the `spawned` record names is the child, as SpawnedChildTests' table gives it with
        `child`'s changes, and it is still running; any other PID is the Heimdall this
        planner started. The real child is a script that exits at once. Returns the goal's
        record, the process calls, the child's PID and Heimdall's process."""
        program = self.root / ("child.cmd" if os.name == "nt" else "child.sh")
        program.write_text("@exit /b 0\r\n" if os.name == "nt" else "#!/bin/sh\nexit 0\n", encoding="utf-8")
        program.chmod(0o700)
        spawned = self.root / "spawned-pid"

        class Launched(RecordedProcesses):
            def open(self, pid):
                if pid not in self.table:
                    if pid != int(spawned.read_text()):
                        self.heimdall = pid
                        self.table[pid] = {"created": 1000, "parent": 1, "image": None, "running": True}
                    else:
                        self.table[pid] = dict({"created": 1001, "parent": self.heimdall,
                                                "image": PureWindowsPath(str(program)), "running": True}, **child)
                return super().open(pid)
        planner = self.planner(mode)
        planner.platform, planner.processes = "nt", Launched({})
        started, popen = [], subprocess.Popen

        def starting(*arguments, **options):
            process = popen(*arguments, **options)
            started.append(process)
            return process
        with patch.object(h2.subprocess, "Popen", starting):
            record = h2.run_goal(planner, {"goal": "run", "profile": "covered", "work_id": "work-6",
                                           "argv": [str(program)]})
        heimdall, = started
        self.assertIsNone(planner.child)
        self.assertIsNotNone(heimdall.returncode)  # Heimdall was ended with the launch
        self.assertEqual(list(self.root.glob("h2-run-*")), [])
        return record, planner.processes.log, int(spawned.read_text()), heimdall

    def test_a_spawned_record_naming_a_process_that_fails_a_check_is_no_launch(self):
        # M07-W7-R03, the planner's use of `hold_spawned` (M07-W8-R04): the `spawned` record
        # names a running process whose parent is not the Heimdall this planner started.
        # It is no launch: the goal fails, Heimdall is ended, and that process is neither
        # held nor terminated by H2.
        record, log, pid, _ = self.launch_held_as_data("spawn-child", parent=1)
        refused = "its parent is not the process this planner started"
        self.assertFalse(record["success"], record)
        self.assertEqual(record["detail"], f"the spawned record names a process that is not the child: {refused}")
        self.assertEqual(record["spawned_child"], {"pid": pid, "held": False, "problem": refused})
        self.assertIn(("facts", f"h{pid}"), log)
        self.assertNotIn(("terminate", f"h{pid}"), log)
        self.assertEqual(log[-2:], [("wait", f"h{pid}", 0), ("close", f"h{pid}")])

    def test_a_launch_that_is_not_up_ends_the_child_it_held(self):
        # M07-W8-R04: Heimdall wrote `launching` and `spawned`, and ended before its child
        # wrote a line (not up). The child it named passes every check and is held, and
        # since the launch is no launch, H2 ends it by its handle, once.
        record, log, pid, heimdall = self.launch_held_as_data("spawn-child-mute")
        self.assertFalse(record["success"], record)
        self.assertEqual(record["detail"], f"the child wrote no line (exit {heimdall.returncode})")
        self.assertEqual(record["spawned_child"], {"pid": pid, "held": True, "ended": "ended_by_handle",
                                                   "exit_code": 1})
        self.assertEqual(log.count(("terminate", f"h{pid}")), 1)
        self.assertEqual(log[-1], ("close", f"h{pid}"))

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

    def test_main_prints_one_summary_and_reports_failure_by_exit_code(self):
        stdout = io.StringIO()
        goals = [json.dumps({"goal": "discover"}), json.dumps(self.access()),
                 json.dumps(self.access("novel", task="novel"))]
        argv = ["--heimdall-bin", str(self.stub), "--scratch-root", str(self.root)]
        for goal in goals:
            argv += ["--goal", goal]
        status = self.whole(argv, STUB, stdout)
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
        # The request answered with a code no table has is uncertain (W8c): the close
        # observed it through the list of bindings, before the release, and it fails the run.
        self.assertEqual(summary["release_attempts"], {})
        self.assertEqual([(entry["call"], entry["profile"], entry["uncertain"],
                           [attempt["outcome"] for attempt in entry["attempts"]])
                          for entry in summary["request_attempts"].values()],
                         [("access ensure", "novel", True, ["still_unknown", "still_unknown"])])
        self.assertEqual(self.calls()[-2], ["inspect", "bindings"])
        self.assertEqual(sorted(summary), ["call_set", "close", "harness", "left_active",
                                           "release_attempts", "request_attempts", "tasks"])
        for task in summary["tasks"]:
            for field in ("calls", "round_trips", "human_handoffs", "invalid_retries",
                          "wall_time_ms", "discovery_bytes", "detail", "skipped", "final_state",
                          "held", "refused_releases", "outcome_unknown", "unanswered", "not_sent",
                          "still_unknown", "not_listed", "requests_unanswered",
                          "requests_not_sent", "requests_still_unknown"):
                self.assertIn(field, task)

    def test_run_is_main_with_the_command_it_is_given(self):
        # W7 item 7: `main` parses its arguments and calls `run` with the executable they
        # name. `run` with the stub started through the interpreter, as the whole-run tests
        # do on Windows, gives the same exit status and summary.
        goals = [{"goal": "discover"}, self.access(), self.access("novel", task="novel"),
                 self.access("uncertain-none", task="e2", expect_refusal="OUTCOME_UNKNOWN")]
        argv = ["--heimdall-bin", str(self.stub), "--scratch-root", str(self.root)]
        for goal in goals:
            argv += ["--goal", json.dumps(goal)]
        summaries = []
        for through_run in (False, True):
            self.fresh()
            self.stub.write_text(f"#!{sys.executable} -IB\n{STUB}" if not through_run else STUB,
                                 encoding="utf-8")
            stdout = io.StringIO()
            with patch.dict(os.environ, self.environment), contextlib.redirect_stdout(stdout):
                if through_run:
                    status = h2.run(h2.parse_arguments(argv), [sys.executable, "-IB", str(self.stub)])
                elif os.name == "posix":
                    self.stub.chmod(0o700)
                    status = h2.main(argv)
                else:
                    continue
            summary = json.loads(stdout.getvalue())
            summaries.append((status, [task["success"] for task in summary["tasks"]], summary["close"],
                              [entry["call"] for entry in summary["request_attempts"].values()]))
        self.assertEqual(summaries[-1], (1, [True, True, False, False],
                                         {"released": ["binding_fixture"], "held": []},
                                         ["access ensure", "access ensure"]))
        self.assertEqual(len(set(map(repr, summaries))), 1)
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                h2.parse_arguments(["--heimdall-bin", "relative", "--scratch-root", str(self.root),
                                    "--goal", "{}"])

    def test_main_exits_1_when_a_release_was_refused_and_names_it(self):
        many = "binding_many_{}".format
        refused = {"binding_id": many(1), "code": "CAPABILITY_UNAVAILABLE", "exit_code": 4}
        default = 'mode = "normal" if'
        self.assertEqual(STUB.count(default), 1)
        stub = STUB.replace(default, f'mode = "refuse:{many(1)}" if')
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
                status = self.whole(argv, stub, stdout)
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

    def test_main_exits_1_when_no_call_about_a_release_was_answered_and_names_every_binding(self):
        # M07-W5-R01, the second probe as a whole run: a stop goal, then the close.
        many = "binding_many_{}".format
        default = 'mode = "normal" if'
        stub = STUB.replace(default, 'mode = "sleep:always:normal" if')
        argv = ["--heimdall-bin", str(self.stub), "--scratch-root", str(self.root)]
        for goal in [self.access("many", task=f"access-{index}") for index in range(3)] + [{"goal": "stop"}]:
            argv += ["--goal", json.dumps(goal)]
        seen, stdout = self.watched(0.3), io.StringIO()
        status = self.whole(argv, stub, stdout)
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
                argv = ["--heimdall-bin", str(self.stub), "--scratch-root", str(self.root)]
                for goal in access + stop * stopped:
                    argv += ["--goal", goal]
                stdout = io.StringIO()
                status = self.whole(argv, stub, stdout)
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
        still = dict(ok, outcome="still_unknown", listed=[], candidates=[])
        unfinished = dict(named, outcome="still_unknown", code="OK", exit_code=5, observed="operation")
        answered = dict(named, by="access", outcome="outcome_unknown", code="OUTCOME_UNKNOWN", exit_code=7)
        accepted = dict(named, by="access", outcome="still_unknown", code=None, exit_code=None,
                        fault="timed_out", detail="a CLI call ran past its time limit",
                        observed="operation")
        seen = self.watched(2.0, limited=(["access", "ensure"], ["operation", "wait"]))
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
             [dict(ok, by="stop", outcome="binding_found", listed=[found], candidates=[found],
                   bindings=[found])], True,
             [["inspect", "bindings"], ["access", "release", found]], False),
            # It named an operation before it stayed, and that operation never ends.
            ("never", "late", {"timeout_ms": 1}, dict(late, code="ACCEPTED", **named),
             [dict(unfinished, by="stop"), dict(unfinished, by="close")], False, [wait] * 2, True),
            # M07 W6c: answered `OUTCOME_UNKNOWN`, and its operation unfinished at the
            # step limit, and after it. The goal's own waits come first.
            ("never", "uncertain", {}, answered,
             [dict(unfinished, by="stop"), dict(unfinished, by="close")], False,
             [wait] * (h2.MAX_STEPS - 1 + 2), True),
            # M07 W6c: answered `ACCEPTED`, and its wait ran past its time limit. The
            # operation never ends.
            ("sleep:wait:never", "covered", {"timeout_ms": 1}, accepted,
             [dict(unfinished, by="stop"), dict(unfinished, by="close")], False, [wait] * 3, True),
            # W7, M07-W6-R03 (E2): answered `OUTCOME_UNKNOWN` naming no operation, with
            # effect `none`, by a goal that expected that code. It is no success, and the
            # run exits 1.
            ("work:binding_second:none", "uncertain-none", {"expect_refusal": "OUTCOME_UNKNOWN"},
             {"by": "access", "outcome": "outcome_unknown", "code": "OUTCOME_UNKNOWN", "exit_code": 7},
             [dict(still, by="stop"), dict(still, by="close")], False, [["inspect", "bindings"]] * 2, True),
            # W7, M07-W6-R01 (G1): answered `ACCEPTED`, and every wait found the operation
            # unfinished until the step limit (Heimdall's own timeout, exit 5).
            ("never", "covered", {"timeout_ms": 1}, dict(unfinished, by="access"),
             [dict(unfinished, by="stop"), dict(unfinished, by="close")], False,
             [wait] * (h2.MAX_STEPS - 1 + 2), True),
        )
        for mode, profile, fields, own, later, stopped, calls, uncertain in rows:
            with self.subTest(mode=mode, profile=profile):
                self.fresh()
                del seen[:]
                stub = STUB.replace(default, f'mode = "{mode}" if')
                argv = ["--heimdall-bin", str(self.stub), "--scratch-root", str(self.root)]
                for goal in (self.access(profile, task="late", **fields), {"goal": "stop"}):
                    argv += ["--goal", json.dumps(goal)]
                stdout = io.StringIO()
                status = self.whole(argv, stub, stdout)
                self.assertEqual(status, 1)
                summary = json.loads(stdout.getvalue())
                self.assertEqual([task["success"] for task in summary["tasks"]], [False, stopped])
                self.assertEqual((summary["close"], summary["release_attempts"]),
                                 ({"released": [], "held": []}, {}))
                request_id = seen[0][7]
                self.assertEqual(summary["request_attempts"], {request_id: {
                    "call": "access ensure", "profile": profile, "work_id": "work-1",
                    "uncertain": uncertain, "attempts": [own, *later]}})
                kept = {"outcome_unknown": "requests_outcome_unknown",
                        "still_unknown": "requests_still_unknown"}.get(own["outcome"], "requests_unanswered")
                self.assertEqual([entry["request_id"] for entry in summary["tasks"][0][kept]], [request_id])
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
