#!/usr/bin/env python3
"""M06-U7: generator dry runs over synthetic logs, run by tests/native/m06/selftest.sh.

Reaches no host and builds nothing. The real case index (tests/native/m06/case-index.json) and the
committed required inventory (tests/native/m06/required-inventory.json) are the inputs; every log
is synthesized from them in a temporary directory, so a run here proves what the generator does
with *this* index, not with a toy one (tests/native/m05/selftest_synthetic.py, the same method).
The inventory is re-stamped with the temporary sources' digest (the committed one is bound to the
commit it was generated at), and the case index is reduced to the targets the committed inventory
holds (HM_SKIP_TARGETS semantics: at a commit that lacks the exit-journey targets the index names
more than the inventory resolved). No test names an exit journey that may not exist yet: the
tests pick their subjects from the inventory.

What is pinned:
  * a run in which every required test passes: every platform row of every case is verified, the
    owner-input rows of m06-plan §7 keep their cases blocked with the input named, ⟨ruling E1⟩ the
    container mechanism and capture rows are deferred_with_decision on ADR-0015, the persistence
    journey is blocked on B3 and the n0-public capture on the owner's authorization, the deferred
    rows never count, and the records the generator writes validate against
    tests/evidence/record.schema.json;
  * the lowest-row rule: with the owner-input rows taken away, a case with a not_started row is
    not_started, never verified;
  * ⟨M06 exit⟩ blocked_commands: a failed macOS command named there blocks the macOS rows on owner
    input B19 (a failed test still outranks it), one that exited 0 is refused, and the committed
    runs template names none;
  * a failed test: only that platform's row is in_progress, never blocked and never verified;
  * a platform that did not run: its rows are blocked with the exact missing platform named;
  * a required test missing from a platform that ran: in_progress (incomplete_run), never blocked;
  * an iroh-feature target a platform could not build (the harness's `feature-blocked-<target>`
    host fact): exactly the rows that need it are blocked on that platform with the fact's reason,
    the other platforms and cases are unaffected, and the record carries the reason;
  * the same with a failed test in the row: in_progress (a failure outranks a blocked reason);
  * an iroh-feature target that is neither run nor recorded as blocked: in_progress, never silent;
  * a feature-blocked fact for a target whose tests are in the logs: an error, nothing written;
  * `m06 observation:` lines reach the row of the test that printed them; the feature facts reach
    the record's environment, and other facts do not;
  * a Unix-only target (`platform_only` with a rationale) is excluded on Windows with the rationale
    on record; without the rationale the Windows row is in_progress;
  * HM_SKIP_TARGETS drops exactly the named targets (and a platform_required map it empties), and
    --write refuses to run with it set;
  * the committed index, runs template and inventory agree with one another, and every test of the
    two exit targets is required by a case;
  * ⟨M06 exit⟩ the Unix-only iroh exit target is never required on Windows;
  * ⟨M06 exit⟩ the windows-controller exit code is the recorder's commands.txt: no commands log, a
    configured exit_codes map and a recorded pass against the journey's own failing trailer are
    refused; import-windows-controller.py scans before writing (canary, SID, home path, address),
    refuses a forged pass, another commit, an extra or missing file and a typed command, never
    overwrites, and fills the configuration;
  * ⟨M06 exit⟩ a journey that printed `journey: blocked` is not a pass: its row is blocked with the
    logged reason (a failure still outranks it), however many lines came before it;
  * ⟨M06 exit⟩ --write refuses unfilled identity fields; fill-run-facts.py fills them from its
    inputs (git and the toolchain stubbed) and refuses a dirty checkout, another commit, a malformed
    or too-late start time, a platform output naming another commit and a platform with no digest.
  * ⟨M06 exit C10b⟩ a platform's run_commit (scratch git repository): outputs must name it, it must
    be an ancestor of HEAD, a run_commit other than HEAD needs a reason, product drift outside
    run_commit_drift_allow is refused, allowed drift reaches the label, and no run_commit is HEAD.
"""

import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def load_m06():
    argv = sys.argv
    spec = importlib.util.spec_from_file_location("m06_evidence", HERE / "m06-evidence.py")
    mod = importlib.util.module_from_spec(spec)
    sys.argv = ["m06-evidence.py"]
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.argv = argv
    return mod


m06 = load_m06()


def load_importer():
    spec = importlib.util.spec_from_file_location("import_windows_controller", HERE / "import-windows-controller.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


IMPORTER = load_importer()
CONTROLLER_COMMAND = IMPORTER.COMMAND
ev = m06.ev
INDEX = json.loads((HERE / "case-index.json").read_text(encoding="utf-8"))
INV = json.loads((HERE / "required-inventory.json").read_text(encoding="utf-8"))
RUNS = json.loads((HERE / "runs.json").read_text(encoding="utf-8"))

PLATFORMS = ("macos", "linux", "windows")
# ⟨M06 W5h⟩ The scenario platform: the Windows controller journey
# (tests/native/m06/run-windows-controller.ps1), whose steps are the scenario target's.
JOURNEY_PLATFORM = "windows-controller"
JOURNEY = "windows-controller-journey"
# ⟨M06 W5k⟩ The cases whose Windows-controller row is the journey. T06 is not one: its
# Windows row is blocked on owner input B2 (a second Windows account), because the journey
# has one controller (m06-plan §3 "Windows controller rows").
JOURNEY_CASES = ("A24",)
# ⟨M06 W5g⟩ The second scenario platform: the cross-host journey (tests/native/m06/run-crosshost.sh:
# the Mac as controller, the devbox as runner), the "Runner" rows of m06-plan §3.
CROSSHOST_PLATFORM = "runner-crosshost"
CROSSHOST = "crosshost-journey"
CROSSHOST_CASES = {"A24": "a24", "A07": "a07", "T06": "t06", "A25": "a25"}
ALL_PLATFORMS = (*PLATFORMS, JOURNEY_PLATFORM, CROSSHOST_PLATFORM)
GROUPS = list(INDEX["groups"])
EXIT_KEY = next(iter(INDEX["exit_claims"]))
# The targets with required-features = ["iroh"] that the case index names (m06-plan U7).
IROH_TARGETS = ("integration_transport_supervise_m06", "e2e_exit_m06_iroh")
IROH_CASE = "A26"
REASON = "the iroh-feature build of heimdall-runtime failed (cargo exit 101): error: linking with `cc` failed (synthetic)"


def inventory_targets():
    out = set()
    for kind in ("groups", "exit_claims"):
        for sec in INV[kind].values():
            out.update(sec["tests"])
    return out


def reduced_index():
    """The case index without the targets the committed inventory lacks."""
    have = inventory_targets()
    named = set()
    for kind in ("groups", "exit_claims"):
        for sec in INDEX[kind].values():
            named.update(sec.get("tests", {}))
    return m06.m05.drop_targets(copy.deepcopy(INDEX), {t for t in named if t not in have})


def log_text(targets, style, observations=None):
    """A platform's log. observations: {(target, test): [lines]} printed under the test's
    `---- <test> stdout ----` header, as libtest's --show-output does."""
    lines = []
    for target, tests in targets.items():
        if style == "cargo":
            if target.endswith("-unit"):
                lines.append(f"     Running unittests src/lib.rs (target/debug/deps/{target[:-len('-unit')]}-0123abcd)")
            else:
                lines.append(f"     Running tests/x/{target}.rs (target/debug/deps/{target}-0123abcd)")
        else:
            lines.append(f"### {target}")
        lines.append(f"running {len(tests)} tests")
        for name, result in tests.items():
            lines.append(f"test {name} ... {result}")
        seen = [(n, ls) for (t, n), ls in (observations or {}).items() if t == target]
        if seen:
            lines += ["", "successes:", ""]
            for name, obs in seen:
                lines += [f"---- {name} stdout ----", *obs, ""]
        if style != "cargo":
            lines.append(f"### {target} exit=0")
    return "\n".join(lines) + "\n"


def passing_logs(index, inv):
    """{platform: {target: {test: result}}}: every test the index requires on that platform
    passes (what a clean native run would print)."""
    logs = {}
    for plat in ALL_PLATFORMS:
        per = {}
        for kind in ("groups", "exit_claims"):
            for sid, sec in index[kind].items():
                if sid not in inv[kind]:
                    continue  # an exit claim made of groups has no tests of its own
                for target, name in ev.required(index, inv, kind, sid, plat):
                    per.setdefault(target, {})[name] = "ok"
                for target, names in ((sec.get("platform_required") or {}).get(plat) or {}).items():
                    for name in names:
                        per.setdefault(target, {})[name] = "ok"
        logs[plat] = per
    return logs


class Scratch:
    """A temporary index, inventory, logs and config; runs the generator's main()."""

    def __init__(self, testcase, index=None, logs=None, platforms=None, facts=None, observations=None, inv=None):
        self.tmp = tempfile.TemporaryDirectory(prefix="m06ev")
        testcase.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        self.dir = d
        (d / "src" / "tests").mkdir(parents=True)
        (d / "src" / "tests" / "a.rs").write_text("fn a() {}\n")
        self.index = copy.deepcopy(index) if index is not None else reduced_index()
        self.inv = copy.deepcopy(inv if inv is not None else INV)
        self.inv["sources_sha256"] = ev.sources_digest(d / "src")
        (d / "case-index.json").write_text(json.dumps(self.index))
        (d / "required-inventory.json").write_text(json.dumps(self.inv))
        self.logs = logs if logs is not None else passing_logs(self.index, self.inv)
        cfg = copy.deepcopy(RUNS)
        cfg.update(
            case_index=str(d / "case-index.json"),
            required_inventory=str(d / "required-inventory.json"),
            sources_root=str(d / "src"),
            summary_out=str(d / "summary.json"),
            artifacts_root=str(d),
            build_commit="0" * 40,
            artifact_digest="a" * 64,
            started_at="2026-11-22T00:00:00+00:00",
            environment={"build_host": {"uname": "synthetic"}},
            commands=["synthetic"],
            evidence_paths=["synthetic"],
        )
        for pname in ALL_PLATFORMS:
            style = "cargo" if pname == "macos" else "harness"
            (d / f"{pname}.log").write_text(log_text(self.logs.get(pname, {}), style, (observations or {}).get(pname)))
            # ⟨M06 exit⟩ The Windows controller journey's commands log is its recorder's one
            # line (record-windows-controller.ps1), as import-windows-controller.py imports it.
            (d / f"{pname}.commands").write_text(
                f"exit 0: {CONTROLLER_COMMAND}\n" if pname == JOURNEY_PLATFORM else "exit 0: the required command\n")
            lines = ["os=synthetic", "secret-thing=must not be kept", *((facts or {}).get(pname, []))]
            (d / f"{pname}.facts").write_text("\n".join(lines) + "\n")
            cfg["platforms"][pname].update(
                logs=[f"{pname}.log"], commands_logs=[f"{pname}.commands"], facts=[f"{pname}.facts"],
                artifact_digest="b" * 64,
            )
        for pname, upd in (platforms or {}).items():
            cfg["platforms"][pname].update(upd)
        self.record_paths = {}
        for sid, rec in cfg["records"].items():
            rec["path"] = str(d / (Path(rec["path"]).name))
            self.record_paths[sid] = Path(rec["path"])
        self.cfg = cfg
        (d / "runs.json").write_text(json.dumps(cfg))

    def run(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                rc = ev.main(["--config", str(self.dir / "runs.json"), *args])
            except SystemExit as e:
                rc = e.code
        summary_path = self.dir / "summary.json"
        summary = json.loads(summary_path.read_text()) if summary_path.exists() else None
        return rc, summary, err.getvalue()

    def records(self):
        return {sid: json.loads(p.read_text()) for sid, p in self.record_paths.items() if p.exists()}


def rows(summary, kind, sid):
    return summary[kind][sid]["rows"]


def row(summary, sid, plat):
    """The one platform row of a case (the owner-input rows carry their own labels)."""
    label = RUNS["platforms"][plat]["label"]
    found = [r for r in rows(summary, "groups", sid) if r["platform"] == label]
    assert len(found) == 1, (sid, plat, found)
    return found[0]


def claim_rows(summary, plat):
    label = RUNS["platforms"][plat]["label"]
    found = [r for r in rows(summary, "exit_claims", EXIT_KEY) if r["platform"] == label]
    assert found, plat
    return found


def a_test(index, sid, plat, skip_targets=()):
    """(target, name) of one test the case requires on the platform."""
    for target, name in ev.required(index, INV, "groups", sid, plat):
        if target not in skip_targets:
            return target, name
    raise AssertionError(f"{sid} requires nothing on {plat}")


def iroh_targets_in(index):
    have = set(index["groups"][IROH_CASE]["tests"])
    return [t for t in IROH_TARGETS if t in have]


def blocked_facts(targets, reason=REASON):
    return [f"feature-targets=iroh:", *[f"feature-blocked-{t}={reason}" for t in targets]]


class CleanRun(unittest.TestCase):
    def test_every_required_test_passing_verifies_every_platform_row(self):
        s = Scratch(self)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        for sid in GROUPS:
            for plat in PLATFORMS:
                self.assertEqual(row(summary, sid, plat)["status"], "verified", (sid, plat, row(summary, sid, plat)))
        for plat in PLATFORMS:
            self.assertEqual({r["status"] for r in claim_rows(summary, plat)}, {"verified"}, plat)

    def test_the_owner_input_rows_keep_every_case_blocked_and_name_the_input(self):
        s = Scratch(self)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        on = {}
        for sid in GROUPS:
            self.assertEqual(summary["groups"][sid]["status"], "blocked", sid)
            on[sid] = " | ".join(r.get("blocked_on", "") for r in rows(summary, "groups", sid) if r["status"] == "blocked")
        for sid in ("A24", "A25", "T06", "A07"):
            self.assertIn("linux-arm64", on[sid], sid)
        self.assertIn("lifecycle", on["A24"])
        self.assertIn("firewall", on["A26"])
        self.assertEqual(summary["exit_claims"][EXIT_KEY]["status"], "blocked")

    def test_the_e1_rows_container_rows_are_deferred_on_adr_0015_and_persistence_and_capture_are_blocked(self):
        """⟨M06 exit, ruling E1⟩ A26's container mechanism and capture rows are
        deferred_with_decision citing ADR-0015 and never count; the persistence journey is
        blocked on owner input B3 and the n0-public capture on the owner's authorization; A25
        has no container row (its limit, "not in a container", is the record's); nothing is
        not_started."""
        s = Scratch(self)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        a26 = rows(summary, "groups", "A26")
        self.assertFalse([r for r in a26 if r["status"] == "not_started"], a26)
        deferred = [r for r in a26 if r["status"] == "deferred_with_decision"]
        self.assertEqual(len(deferred), 2, deferred)
        self.assertTrue(any("ADR-0015" in r["decision"] and "containers" in r["platform"] for r in deferred))
        self.assertTrue(any("§5" in r["decision"] for r in deferred))
        blocked = {r["platform"]: r["blocked_on"] for r in a26 if r["status"] == "blocked" and "Keychain" in r["platform"] + r.get("blocked_on", "")}
        self.assertEqual(len(blocked), 1, blocked)
        self.assertIn("owner input B3", next(iter(blocked.values())))
        capture = [r for r in a26 if "n0-public" in r["platform"]]
        self.assertEqual([r["status"] for r in capture], ["blocked"], capture)
        self.assertIn("authorization", capture[0]["blocked_on"])
        a25 = rows(summary, "groups", "A25")
        self.assertFalse([r for r in a25 if r["status"] == "not_started" or "container" in r["platform"]], a25)
        self.assertTrue(any("not in a container" in x.lower() for x in RUNS["records"]["A25"]["limitations"]))
        for sid in GROUPS:
            self.assertFalse([r for r in rows(summary, "groups", sid) if r["status"] == "not_started"], sid)

    def test_without_the_owner_input_rows_the_deferred_rows_never_count_and_a_not_started_row_still_lowers(self):
        # ⟨M06 W5g⟩ A07 declares the cross-host row too, so "every row ran" needs that journey's
        # steps resolved and passed (the committed inventory may predate the scenario).
        index, inv = crosshost_fixture()
        for sid in GROUPS:
            index["groups"][sid]["blocked_rows"] = [r for r in index["groups"][sid]["blocked_rows"] if r["status"] != "blocked"]
        s = Scratch(self, index=index, inv=inv)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        # ⟨ruling E1⟩ A26's remaining rows are deferred, so they never count; A25 has none left.
        self.assertEqual(summary["groups"]["A26"]["status"], "verified")
        self.assertEqual(summary["groups"]["A25"]["status"], "verified")
        self.assertEqual(summary["groups"]["A07"]["status"], "verified")
        # The lowest-row rule: one not_started row keeps its case, and the claim, not_started.
        index["groups"]["A26"]["blocked_rows"].append(
            {"platform": "a synthetic row with no run", "status": "not_started", "not_configured": "synthetic"})
        rc, summary, err = Scratch(self, index=index, inv=inv).run()
        self.assertEqual(rc, 0, err)
        self.assertEqual(summary["groups"]["A26"]["status"], "not_started")
        self.assertEqual(summary["groups"]["A07"]["status"], "verified")
        self.assertEqual(summary["exit_claims"][EXIT_KEY]["status"], "not_started")

    # ⟨M06 exit, ruling 2026-11-24⟩ blocked_commands (tests/native/m02/m02-evidence.py): the macOS
    # owner-metadata step, failed for want of owner input B19, lowers macOS's rows to blocked on it.
    B19 = {"the required command": {"owner_input": "B19", "reason": "owner attribution of the ~/.ssh metadata change"}}

    def test_a_blocked_command_blocks_the_macos_rows_on_b19_and_hides_no_failure(self):
        s = Scratch(self, platforms={"macos": {"blocked_commands": self.B19}})
        (s.dir / "macos.commands").write_text("exit 1: the required command\n")
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        for sid in GROUPS:
            r = row(summary, sid, "macos")
            self.assertEqual(r["status"], "blocked", (sid, r))
            self.assertIn("owner input B19", r["blocked_on"])
            self.assertIn("~/.ssh metadata change", r["blocked_on"])
            self.assertEqual(r["exit_codes"]["the required command"], 1)
            self.assertIn("the required command", r["failed_commands_blocked_on"])
            self.assertEqual(row(summary, sid, "linux")["status"], "verified", sid)
        # A failed test on macOS still outranks it.
        logs = passing_logs(s.index, s.inv)
        target, name = a_test(s.index, "A24", "macos")
        logs["macos"][target][name] = "FAILED"
        s = Scratch(self, logs=logs, platforms={"macos": {"blocked_commands": self.B19}})
        (s.dir / "macos.commands").write_text("exit 1: the required command\n")
        rc, summary, err = s.run()
        self.assertEqual(row(summary, "A24", "macos")["status"], "in_progress")

    def test_a_blocked_command_that_exited_zero_is_refused_and_nothing_is_written(self):
        s = Scratch(self, platforms={"macos": {"blocked_commands": self.B19}})
        rc, summary, err = s.run("--write")
        self.assertEqual(rc, 2, err)
        self.assertIn("exited 0", err)
        self.assertEqual(s.records(), {})

    def test_the_committed_runs_template_names_no_blocked_command(self):
        # Whether macOS uses B19 is ruled later; the integrator adds it to the exit config.
        for pname, p in RUNS["platforms"].items():
            self.assertNotIn("blocked_commands", p, pname)

    def test_the_written_records_validate_and_carry_the_owner_inputs(self):
        s = Scratch(self)
        rc, summary, err = s.run("--write")
        self.assertEqual(rc, 0, err)
        recs = s.records()
        self.assertEqual(set(recs), set(GROUPS) | {EXIT_KEY})
        for sid, rec in recs.items():
            self.assertEqual(ev.validate_record(rec), [], sid)
            self.assertEqual(rec["status"], "blocked", sid)
            self.assertTrue(rec["blocked_on"], sid)
        self.assertIn("linux-arm64", recs["A24"]["blocked_on"])
        self.assertEqual(recs[EXIT_KEY]["case_id"], "m06-exit-claims")
        self.assertEqual(recs["A26"]["case_id"], "A26")


class FailuresAndGaps(unittest.TestCase):
    def test_a_failed_test_keeps_only_its_platform_row_in_progress(self):
        index = reduced_index()
        logs = passing_logs(index, INV)
        target, name = a_test(index, "A24", "linux")
        logs["linux"][target][name] = "FAILED"
        s = Scratch(self, index=index, logs=logs)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        r = row(summary, "A24", "linux")
        self.assertEqual(r["status"], "in_progress")
        self.assertIn(f"{target}::{name}", r["failed"])
        self.assertEqual(row(summary, "A24", "macos")["status"], "verified")
        self.assertIn("in_progress", {x["status"] for x in claim_rows(summary, "linux")})
        self.assertEqual({x["status"] for x in claim_rows(summary, "macos")}, {"verified"})

    def test_a_platform_that_did_not_run_is_blocked_with_the_exact_missing_platform(self):
        index = reduced_index()
        logs = passing_logs(index, INV)
        logs["windows"] = {}
        reason = "the Windows 11 x64 PC: no native run at this commit (synthetic)"
        s = Scratch(self, index=index, logs=logs, platforms={"windows": {"unavailable": reason}})
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        for sid in GROUPS:
            r = row(summary, sid, "windows")
            self.assertEqual(r["status"], "blocked", sid)
            self.assertEqual(r["blocked_on"], reason, sid)
            self.assertEqual(row(summary, sid, "macos")["status"], "verified", sid)
        self.assertEqual({r["status"] for r in claim_rows(summary, "windows")}, {"blocked"})

    def test_a_required_test_missing_from_a_platform_that_ran_is_in_progress_never_blocked(self):
        index = reduced_index()
        logs = passing_logs(index, INV)
        target, name = a_test(index, "A07", "linux")
        del logs["linux"][target][name]
        s = Scratch(self, index=index, logs=logs)
        rc, summary, err = s.run()
        r = row(summary, "A07", "linux")
        self.assertEqual(r["status"], "in_progress")
        self.assertIn(f"{target}::{name}", r["incomplete_run"])
        self.assertNotIn("blocked_on", r)
        self.assertEqual(row(summary, "A07", "macos")["status"], "verified")

    def test_a_whole_target_missing_from_a_platform_that_ran_is_in_progress_and_named(self):
        index = reduced_index()
        logs = passing_logs(index, INV)
        target, _ = a_test(index, "A25", "linux")
        del logs["linux"][target]
        s = Scratch(self, index=index, logs=logs)
        rc, summary, err = s.run()
        r = row(summary, "A25", "linux")
        self.assertEqual(r["status"], "in_progress")
        self.assertIn(target, r["missing_targets"])


class IrohFeature(unittest.TestCase):
    def setUp(self):
        self.index = reduced_index()
        self.targets = iroh_targets_in(self.index)
        self.assertTrue(self.targets, "the case index names an iroh-feature target the inventory holds")

    def blocked_on_linux(self, **kw):
        logs = passing_logs(self.index, INV)
        for t in self.targets:
            logs["linux"].pop(t, None)
        return Scratch(self, index=self.index, logs=logs, facts={"linux": blocked_facts(self.targets)}, **kw), logs

    def test_a_platform_that_could_not_build_the_iroh_targets_has_exactly_those_rows_blocked_with_the_reason(self):
        s, _ = self.blocked_on_linux()
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        r = row(summary, IROH_CASE, "linux")
        self.assertEqual(r["status"], "blocked", r)
        self.assertEqual(r["blocked_on"], f"linux: {REASON}")
        self.assertGreater(r["passed"], 0, "the row's other targets ran and passed")
        self.assertTrue(all(q.split("::")[0] in self.targets for q in r["not_run_on_this_platform"]))
        # Only that case on that platform.
        self.assertEqual(row(summary, IROH_CASE, "macos")["status"], "verified")
        self.assertEqual(row(summary, IROH_CASE, "windows")["status"], "verified")
        for sid in GROUPS:
            if sid != IROH_CASE:
                self.assertEqual(row(summary, sid, "linux")["status"], "verified", sid)

    def test_the_record_carries_the_reason_and_the_feature_facts_and_no_other_fact(self):
        s, _ = self.blocked_on_linux()
        rc, summary, err = s.run("--write")
        self.assertEqual(rc, 0, err)
        rec = s.records()[IROH_CASE]
        self.assertEqual(ev.validate_record(rec), [])
        self.assertIn(f"linux: {REASON}", rec["blocked_on"])
        facts = rec["environment"]["host_facts"]["linux"]
        self.assertEqual(facts[f"feature-blocked-{self.targets[0]}"], REASON)
        self.assertIn("feature-targets", facts)
        self.assertNotIn("secret-thing", json.dumps(rec))

    def test_a_failed_test_in_the_same_row_outranks_the_blocked_reason(self):
        s, logs = self.blocked_on_linux()
        target, name = a_test(self.index, IROH_CASE, "linux", skip_targets=self.targets)
        logs["linux"][target][name] = "FAILED"
        s = Scratch(self, index=self.index, logs=logs, facts={"linux": blocked_facts(self.targets)})
        rc, summary, err = s.run()
        r = row(summary, IROH_CASE, "linux")
        self.assertEqual(r["status"], "in_progress", r)
        self.assertIn(f"{target}::{name}", r["failed"])
        self.assertEqual(r["missing_capabilities"], [f"linux: {REASON}"])
        self.assertNotIn("blocked_on", r)

    def test_an_iroh_target_neither_run_nor_recorded_as_blocked_is_in_progress_never_silent(self):
        logs = passing_logs(self.index, INV)
        for t in self.targets:
            logs["linux"].pop(t, None)
        s = Scratch(self, index=self.index, logs=logs)
        rc, summary, err = s.run()
        r = row(summary, IROH_CASE, "linux")
        self.assertEqual(r["status"], "in_progress", r)
        self.assertEqual(sorted(r["missing_targets"]), sorted(self.targets))
        self.assertNotIn("blocked_on", r)

    def test_every_platform_blocked_on_the_feature_leaves_no_verified_row_and_is_not_an_evaluation_error(self):
        logs = passing_logs(self.index, INV)
        for plat in PLATFORMS:
            for t in self.targets:
                logs[plat].pop(t, None)
        s = Scratch(self, index=self.index, logs=logs, facts={p: blocked_facts(self.targets) for p in PLATFORMS})
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        for plat in PLATFORMS:
            self.assertEqual(row(summary, IROH_CASE, plat)["status"], "blocked", plat)

    def test_a_blocked_fact_for_a_target_whose_tests_are_in_the_logs_is_an_error_and_nothing_is_written(self):
        logs = passing_logs(self.index, INV)
        s = Scratch(self, index=self.index, logs=logs, facts={"linux": blocked_facts(self.targets[:1])})
        rc, summary, err = s.run("--write")
        self.assertEqual(rc, 2)
        self.assertIn("recorded as feature-blocked but its tests are in the logs", err)
        self.assertEqual(s.records(), {})

    def test_a_reason_runs_json_gives_is_kept_beside_the_harness_fact(self):
        s, logs = self.blocked_on_linux(platforms={"linux": {"missing_capabilities": {self.targets[0]: "configured reason"}}})
        rc, summary, err = s.run()
        r = row(summary, IROH_CASE, "linux")
        self.assertEqual(r["status"], "blocked")
        self.assertIn("configured reason", r["blocked_on"])
        self.assertIn(REASON, r["blocked_on"])

    def test_the_fact_parser_takes_only_feature_blocked_facts_with_a_target_and_a_reason(self):
        got = m06.feature_blocked({"feature-blocked-t_a": " why ", "feature-blocked-": "x", "feature-blocked-t_b": " ",
                                   "feature-targets": "iroh: t_c", "os": "x"})
        self.assertEqual(got, {"t_a": "why"})


class Observations(unittest.TestCase):
    def test_m06_observation_lines_reach_the_row_of_the_test_that_printed_them(self):
        index = reduced_index()
        target, name = a_test(index, "A24", "linux")
        obs = {plat: {(target, name): [f"m06 observation: a24 readiness: earliest bound reported ({plat})", "not an observation"]}
               for plat in ("linux", "macos")}
        s = Scratch(self, index=index, observations=obs)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        for plat in ("linux", "macos"):
            seen = row(summary, "A24", plat)["observations"]
            self.assertEqual(seen[f"{target}::{name}"], [f"m06 observation: a24 readiness: earliest bound reported ({plat})"])
        self.assertNotIn("observations", row(summary, "A24", "windows"))


class PlatformOnly(unittest.TestCase):
    KEY = "e2e_environment_runner_m06"

    def test_a_unix_only_target_is_excluded_on_windows_with_its_rationale_on_record(self):
        s = Scratch(self)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        w = row(summary, "A24", "windows")
        self.assertGreater(w["excluded_by_rationale"][self.KEY], 0)
        self.assertFalse(w.get("excluded_without_rationale"))
        self.assertNotIn(self.KEY, s.logs["windows"])
        self.assertIn(self.KEY, s.logs["linux"])

    def test_the_same_exclusion_without_a_rationale_keeps_the_windows_row_in_progress(self):
        index = reduced_index()
        del index["platform_only"][self.KEY]
        s = Scratch(self, index=index, logs=passing_logs(reduced_index(), INV))
        rc, summary, err = s.run()
        w = row(summary, "A24", "windows")
        self.assertEqual(w["status"], "in_progress")
        self.assertTrue(w.get("excluded_without_rationale") or w.get("incomplete_run"), w)

    def test_the_iroh_exit_target_is_unix_only_so_the_windows_a26_row_never_requires_it(self):
        # ⟨M06 exit; RESEARCH §0 item 2⟩ #![cfg(unix)]: the Windows feature build holds no test.
        self.assertEqual(INDEX["platform_only"]["e2e_exit_m06_iroh"]["platforms"], ["macos", "linux"])
        index = reduced_index()
        if "e2e_exit_m06_iroh" not in index["groups"]["A26"]["tests"]:
            self.skipTest("the committed inventory lacks the iroh exit target")
        self.assertFalse([t for t, _ in ev.required(index, INV, "groups", "A26", "windows") if t == "e2e_exit_m06_iroh"])
        self.assertTrue([t for t, _ in ev.required(index, INV, "groups", "A26", "linux") if t == "e2e_exit_m06_iroh"])
        s = Scratch(self, index=index)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        w = row(summary, "A26", "windows")
        self.assertEqual(w["status"], "verified", w)
        self.assertGreater(w["excluded_by_rationale"]["e2e_exit_m06_iroh"], 0)

    def test_every_platform_only_entry_of_the_index_has_a_one_line_rationale(self):
        for key, entry in INDEX["platform_only"].items():
            self.assertTrue(entry["rationale"].strip(), key)
            self.assertNotIn("\n", entry["rationale"], key)
            self.assertTrue(set(entry["platforms"]) <= set(PLATFORMS), key)


def journey_fixture():
    """(index, inventory) in which the journey's steps are resolved, as a regenerated
    inventory holds them (the committed one may predate the scenario)."""
    index = reduced_index()
    inv = copy.deepcopy(INV)
    for sid in JOURNEY_CASES:
        steps = INDEX["groups"][sid]["tests"][JOURNEY]
        index["groups"][sid]["tests"][JOURNEY] = list(steps)
        index["groups"][sid]["platform_required"] = {JOURNEY_PLATFORM: {JOURNEY: list(steps)}}
        inv["groups"][sid]["tests"][JOURNEY] = list(steps)
    return index, inv


class WindowsControllerJourney(unittest.TestCase):
    """⟨M06 W5h⟩ The Windows-controller rows of A24 and T06 are the journey's steps on the
    scenario platform (ADR-0012 §2.6; m06-plan §3 "Windows controller rows")."""

    def test_the_index_points_the_windows_controller_rows_at_the_journeys_steps(self):
        scenario = INDEX["scenario_targets"][JOURNEY]
        self.assertEqual(scenario["platforms"], [JOURNEY_PLATFORM])
        self.assertEqual(INDEX["platforms"][JOURNEY_PLATFORM], {"runs": "scenario"})
        self.assertEqual(ev.check_index(INDEX), [])
        for sid in JOURNEY_CASES:
            sec = INDEX["groups"][sid]
            self.assertIn(JOURNEY_PLATFORM, sec["declared_platforms"])
            required = sec["platform_required"][JOURNEY_PLATFORM][JOURNEY]
            self.assertEqual(required, sec["tests"][JOURNEY])
            self.assertTrue(set(required) <= set(scenario["steps"]), sid)
            self.assertNotIn("windows", sec["platform_required"], "the Unix-only suite is not required on Windows")
        self.assertEqual(list(INDEX["groups"]["A24"]["tests"][JOURNEY]), list(scenario["steps"]))
        # The script's own step list is the scenario's, in order.
        script = (HERE / "run-windows-controller.ps1").read_text(encoding="utf-8")
        named = ev.re.findall(r"@\{ Test = '([a-z0-9_]+)'; Case = '(a\d\d)'; Step = '([a-z-]+)' \}", script)
        self.assertEqual([t for t, _, _ in named], list(scenario["steps"]))
        for test, case, step in named:
            self.assertEqual(test, f"{case}_{step.replace('-', '_')}")
        self.assertIn(JOURNEY_PLATFORM, RUNS["platforms"])
        self.assertEqual(RUNS["platforms"][JOURNEY_PLATFORM]["logs"], [f"{JOURNEY_PLATFORM}/tests.txt"])
        self.assertEqual(INDEX["platform_only"]["e2e_exit_m06"]["platforms"], ["macos", "linux"])

    def test_t06_on_windows_is_blocked_on_the_second_windows_account_not_the_journey(self):
        """⟨M06 W5k⟩ m06-plan §3 "Windows controller rows": T06's Windows row is `blocked` on
        owner input B2. The journey has one controller, so it is neither required for T06 nor
        able to verify it, and the row is never `not_started` or inherited."""
        sec = INDEX["groups"]["T06"]
        self.assertNotIn(JOURNEY_PLATFORM, sec["declared_platforms"])
        self.assertNotIn(JOURNEY_PLATFORM, sec["platform_required"])
        self.assertNotIn(JOURNEY, sec["tests"])
        declared = [r for r in sec["blocked_rows"] if "windows" in r["platform"].lower()]
        self.assertEqual(len(declared), 1, declared)
        self.assertEqual(declared[0]["status"], "blocked")
        self.assertIn("owner input B2", declared[0]["blocked_on"])
        self.assertIn("second Windows account", declared[0]["blocked_on"])
        # A fully passing journey leaves that row blocked and gives T06 no journey row.
        index, inv = journey_fixture()
        rc, summary, err = Scratch(self, index=index, inv=inv).run()
        self.assertEqual(rc, 0, err)
        t06 = rows(summary, "groups", "T06")
        label = RUNS["platforms"][JOURNEY_PLATFORM]["label"]
        self.assertFalse([r for r in t06 if r["platform"] == label], t06)
        blocked = [r for r in t06 if "windows controller row" in r["platform"]]
        self.assertEqual([r["status"] for r in blocked], ["blocked"], t06)
        self.assertIn("owner input B2", str(blocked[0]))

    def test_a_passing_journey_verifies_the_row_and_carries_its_observations(self):
        index, inv = journey_fixture()
        line = "m06 observation: a24 pair: owner_enrolled=true session_agent=named_pipe"
        s = Scratch(self, index=index, inv=inv, observations={JOURNEY_PLATFORM: {(JOURNEY, "a24_pair"): [line]}})
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        for sid in JOURNEY_CASES:
            r = row(summary, sid, JOURNEY_PLATFORM)
            self.assertEqual(r["status"], "verified", r)
        self.assertEqual(row(summary, "A24", JOURNEY_PLATFORM)["observations"][f"{JOURNEY}::a24_pair"], [line])

    def test_a_failed_step_keeps_only_the_journey_row_in_progress(self):
        index, inv = journey_fixture()
        logs = passing_logs(index, inv)
        logs[JOURNEY_PLATFORM][JOURNEY]["a07_reconnect"] = "FAILED"
        rc, summary, err = Scratch(self, index=index, inv=inv, logs=logs).run()
        self.assertEqual(rc, 0, err)
        for sid in JOURNEY_CASES:
            self.assertEqual(row(summary, sid, JOURNEY_PLATFORM)["status"], "in_progress")
            self.assertEqual(row(summary, sid, "macos")["status"], "verified")

    def test_steps_that_did_not_run_are_ignored_and_the_row_is_in_progress(self):
        index, inv = journey_fixture()
        logs = passing_logs(index, inv)
        # The script stops at the first failure and writes the later steps `ignored`.
        logs[JOURNEY_PLATFORM][JOURNEY]["a07_barrier"] = "FAILED"
        for step in ("a24_controller_leaves", "a24_onward_managed", "a24_no_controller_socket"):
            logs[JOURNEY_PLATFORM][JOURNEY][step] = "ignored"
        rc, summary, err = Scratch(self, index=index, inv=inv, logs=logs).run()
        self.assertEqual(rc, 0, err)
        r = row(summary, "A24", JOURNEY_PLATFORM)
        self.assertEqual(r["status"], "in_progress", r)
        self.assertEqual(r["platform_required_not_passed"][f"{JOURNEY}::a24_onward_managed"], "ignored")
        self.assertEqual(r["platform_required_not_passed"][f"{JOURNEY}::a07_barrier"], "FAILED")

    def test_a_log_that_lacks_a_planned_step_is_refused_not_read_as_a_shorter_journey(self):
        index, inv = journey_fixture()
        logs = passing_logs(index, inv)
        del logs[JOURNEY_PLATFORM][JOURNEY]["a24_onward_managed"]
        rc, _, err = Scratch(self, index=index, inv=inv, logs=logs).run()
        self.assertEqual(rc, 1)
        self.assertIn(f"{JOURNEY}::a24_onward_managed not found in any log", err)

    def test_a_journey_that_did_not_run_is_blocked_on_its_exact_platform(self):
        index, inv = journey_fixture()
        why = "the Windows PC with WSL 2 and its existing distribution (the journey did not run)"
        s = Scratch(self, index=index, inv=inv, platforms={JOURNEY_PLATFORM: {"unavailable": why, "logs": [], "commands_logs": [], "facts": []}})
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        r = row(summary, "A24", JOURNEY_PLATFORM)
        self.assertEqual(r["status"], "blocked", r)
        self.assertIn("Windows PC", r["blocked_on"])

    def test_the_scripts_log_is_what_the_generator_reads(self):
        # The rehearsal's own log format, as the script writes it (a failed step has no
        # observation and the steps after it no line).
        text = (
            f"### {JOURNEY}\n\nrunning 2 tests\ntest a24_pair ... ok\ntest a24_approve ... FAILED\n\nsuccesses:\n\n"
            "---- a24_pair stdout ----\nm06 observation: a24 pair: owner_enrolled=true\n\n\nfailures:\n\n"
            "---- a24_approve stdout ----\nfailed: code=CAPABILITY_UNAVAILABLE\n\n"
            f"test result: FAILED. 1 passed; 1 failed; 0 ignored\n### {JOURNEY} exit=1\n"
        )
        with tempfile.TemporaryDirectory(prefix="m06j") as d:
            path = Path(d) / "tests.txt"
            path.write_text(text)
            self.assertEqual(ev.parse_log(path), {JOURNEY: {"a24_pair": "ok", "a24_approve": "FAILED"}})
            self.assertEqual(
                ev.parse_observations(path), {JOURNEY: {"a24_pair": ["m06 observation: a24 pair: owner_enrolled=true"]}}
            )


def crosshost_fixture():
    """(index, inventory) in which the cross-host journey's steps are resolved, as a
    regenerated inventory holds them (the committed one may predate the scenario)."""
    index = reduced_index()
    inv = copy.deepcopy(INV)
    for sid in CROSSHOST_CASES:
        steps = INDEX["groups"][sid]["tests"][CROSSHOST]
        index["groups"][sid]["tests"][CROSSHOST] = list(steps)
        index["groups"][sid].setdefault("platform_required", {})[CROSSHOST_PLATFORM] = {CROSSHOST: list(steps)}
        inv["groups"][sid]["tests"][CROSSHOST] = list(steps)
    return index, inv


class CrossHostJourney(unittest.TestCase):
    """⟨M06 W5g⟩ The cross-machine "Runner" rows of A24, A07, T06 and A25 are the cross-host
    journey's steps on its scenario platform (m06-plan §3, §4)."""

    def plan(self):
        r = subprocess.run(["bash", str(HERE / "run-crosshost.sh"), "--plan"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return [line.split() for line in r.stdout.splitlines()]

    def test_the_index_points_the_runner_rows_at_the_journeys_steps_and_the_script_plans_exactly_them(self):
        scenario = INDEX["scenario_targets"][CROSSHOST]
        self.assertEqual(scenario["platforms"], [CROSSHOST_PLATFORM])
        self.assertEqual(INDEX["platforms"][CROSSHOST_PLATFORM], {"runs": "scenario"})
        self.assertEqual(ev.check_index(INDEX), [])
        plan = self.plan()
        self.assertEqual([t for t, _, _ in plan], list(scenario["steps"]), "the script's plan is the scenario's, in order")
        for test, case, step in plan:
            self.assertEqual(test, f"{case}_{step.replace('-', '_')}")
            self.assertTrue(scenario["steps"][test].startswith(f"{step}: "), test)
        for sid, case in CROSSHOST_CASES.items():
            sec = INDEX["groups"][sid]
            self.assertIn(CROSSHOST_PLATFORM, sec["declared_platforms"])
            required = sec["platform_required"][CROSSHOST_PLATFORM][CROSSHOST]
            self.assertEqual(required, sec["tests"][CROSSHOST])
            self.assertEqual(required, [t for t, c, _ in plan if c == case], sid)
            self.assertTrue(sec["crosshost_note"].strip())
        self.assertNotIn(CROSSHOST, INDEX["groups"]["A26"]["tests"], "A26 has no step in this journey")
        self.assertEqual(RUNS["platforms"][CROSSHOST_PLATFORM]["logs"], [f"{CROSSHOST_PLATFORM}/tests.txt"])
        self.assertEqual(RUNS["platforms"][CROSSHOST_PLATFORM]["facts"], [f"{CROSSHOST_PLATFORM}/host.txt"])
        # The Windows controller rows are untouched by it.
        self.assertEqual(set(INDEX["groups"]["A24"]["platform_required"]), {JOURNEY_PLATFORM, CROSSHOST_PLATFORM})
        self.assertEqual(set(INDEX["groups"]["T06"]["platform_required"]), {CROSSHOST_PLATFORM})

    def test_a_passing_journey_verifies_the_four_rows_and_carries_its_observations(self):
        index, inv = crosshost_fixture()
        line = "m06 observation: a24 no-controller-socket: mgmt_sshd_new_connections_in_window=0"
        obs = {CROSSHOST_PLATFORM: {(CROSSHOST, "a24_no_controller_socket"): [line]}}
        rc, summary, err = Scratch(self, index=index, inv=inv, observations=obs).run()
        self.assertEqual(rc, 0, err)
        for sid in CROSSHOST_CASES:
            r = row(summary, sid, CROSSHOST_PLATFORM)
            self.assertEqual(r["status"], "verified", r)
        self.assertEqual(
            row(summary, "A24", CROSSHOST_PLATFORM)["observations"][f"{CROSSHOST}::a24_no_controller_socket"], [line]
        )

    def test_a_failed_step_keeps_only_its_cases_cross_host_row_in_progress(self):
        index, inv = crosshost_fixture()
        logs = passing_logs(index, inv)
        logs[CROSSHOST_PLATFORM][CROSSHOST]["a07_reconnect"] = "FAILED"
        for step in ("a07_barrier", "a07_no_stale_reactivation"):
            logs[CROSSHOST_PLATFORM][CROSSHOST][step] = "ignored"
        rc, summary, err = Scratch(self, index=index, inv=inv, logs=logs).run()
        self.assertEqual(rc, 0, err)
        r = row(summary, "A07", CROSSHOST_PLATFORM)
        self.assertEqual(r["status"], "in_progress", r)
        self.assertEqual(r["platform_required_not_passed"][f"{CROSSHOST}::a07_reconnect"], "FAILED")
        self.assertEqual(r["platform_required_not_passed"][f"{CROSSHOST}::a07_barrier"], "ignored")
        # Each journey has its own runner installation: another case's row is not touched,
        # and no single-host row is.
        self.assertEqual(row(summary, "A24", CROSSHOST_PLATFORM)["status"], "verified")
        self.assertEqual(row(summary, "A07", "linux")["status"], "verified")

    def test_a_journey_that_was_not_selected_is_ignored_and_never_verified(self):
        index, inv = crosshost_fixture()
        logs = passing_logs(index, inv)
        for step in INDEX["groups"]["T06"]["tests"][CROSSHOST]:
            logs[CROSSHOST_PLATFORM][CROSSHOST][step] = "ignored"
        rc, summary, err = Scratch(self, index=index, inv=inv, logs=logs).run()
        self.assertEqual(rc, 0, err)
        self.assertEqual(row(summary, "T06", CROSSHOST_PLATFORM)["status"], "in_progress")
        self.assertEqual(row(summary, "A25", CROSSHOST_PLATFORM)["status"], "verified")

    def test_a_log_that_lacks_a_planned_step_is_refused(self):
        index, inv = crosshost_fixture()
        logs = passing_logs(index, inv)
        del logs[CROSSHOST_PLATFORM][CROSSHOST]["a24_bound"]
        rc, _, err = Scratch(self, index=index, inv=inv, logs=logs).run()
        self.assertEqual(rc, 1)
        self.assertIn(f"{CROSSHOST}::a24_bound not found in any log", err)

    def test_a_journey_that_did_not_run_is_blocked_on_its_exact_platform(self):
        index, inv = crosshost_fixture()
        why = "the devbox as a runner host of its own (the cross-host journey did not run)"
        plats = {CROSSHOST_PLATFORM: {"unavailable": why, "logs": [], "commands_logs": [], "facts": []}}
        rc, summary, err = Scratch(self, index=index, inv=inv, platforms=plats).run()
        self.assertEqual(rc, 0, err)
        for sid in CROSSHOST_CASES:
            r = row(summary, sid, CROSSHOST_PLATFORM)
            self.assertEqual(r["status"], "blocked", r)
            self.assertIn("devbox", r["blocked_on"])
        self.assertEqual(row(summary, "A24", "linux")["status"], "verified")

    def test_the_scripts_own_log_is_what_the_generator_reads(self):
        # The log the script's tool writes for a partial run: a passed step, a failed one, and
        # every other planned step `ignored`.
        with tempfile.TemporaryDirectory(prefix="m06x") as d:
            results = Path(d) / "results.tsv"
            results.write_text(
                "a24_pair\ta24\tpair\tok\towner_enrolled=true\n"
                "a24_approve\ta24\tapprove\tfailed\tcode=CAPABILITY_UNAVAILABLE at /home/x\n"
            )
            planned = Path(d) / "planned"
            planned.write_text("".join(f"{t}\n" for t, _, _ in self.plan()))
            out = subprocess.run(
                [sys.executable, "-I", str(HERE / "crosshost-tool.py"), "log", "--target", CROSSHOST,
                 "--results", str(results), "--planned", str(planned), "--exit", "1"],
                capture_output=True, text=True,
            )
            self.assertEqual(out.returncode, 0, out.stderr)
            path = Path(d) / "tests.txt"
            path.write_text(out.stdout)
            parsed = ev.parse_log(path)[CROSSHOST]
            self.assertEqual(parsed["a24_pair"], "ok")
            self.assertEqual(parsed["a24_approve"], "FAILED")
            self.assertEqual(parsed["a25_sshd_policy_unverified"], "ignored")
            self.assertEqual(len(parsed), len(INDEX["scenario_targets"][CROSSHOST]["steps"]))
            self.assertEqual(
                ev.parse_observations(path), {CROSSHOST: {"a24_pair": ["m06 observation: a24 pair: owner_enrolled=true"]}}
            )
            self.assertNotIn("/home/x", out.stdout, "a failure reason loses its paths")


class ControllerExitCode(unittest.TestCase):
    """⟨M06 exit; RESEARCH §0 item 1⟩ The windows-controller platform's exit code is the
    recorder's commands.txt (record-windows-controller.ps1), never a configured map."""

    def journey_logs(self, trailer=0, recorded=0):
        index, inv = journey_fixture()
        s = Scratch(self, index=index, inv=inv)
        log = s.dir / f"{JOURNEY_PLATFORM}.log"
        log.write_text(ev.re.sub(rf"(?m)^### {JOURNEY} exit=\d+$", f"### {JOURNEY} exit={trailer}", log.read_text()))
        (s.dir / f"{JOURNEY_PLATFORM}.commands").write_text(f"exit {recorded}: {CONTROLLER_COMMAND}\n")
        return s

    def reconfigure(self, s, **upd):
        cfg = json.loads((s.dir / "runs.json").read_text())
        cfg["platforms"][JOURNEY_PLATFORM].update(upd)
        (s.dir / "runs.json").write_text(json.dumps(cfg))

    def test_the_template_reads_the_recorders_commands_log_and_the_scripts_share_its_command(self):
        self.assertEqual(RUNS["platforms"][JOURNEY_PLATFORM]["commands_logs"], [f"{JOURNEY_PLATFORM}/commands.txt"])
        self.assertNotIn("exit_codes", RUNS["platforms"][JOURNEY_PLATFORM])
        ps1 = (HERE / "record-windows-controller.ps1").read_text(encoding="utf-8")
        self.assertIn(f"$Command = '{CONTROLLER_COMMAND}'", ps1)
        self.assertIn(m06.CONTROLLER_SCRIPT, CONTROLLER_COMMAND)

    def test_the_recorded_pass_verifies_the_row(self):
        s = self.journey_logs()
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        self.assertEqual(row(summary, "A24", JOURNEY_PLATFORM)["status"], "verified")

    def test_no_commands_log_is_refused_not_read_as_a_shorter_record(self):
        s = self.journey_logs()
        self.reconfigure(s, commands_logs=[])
        rc, summary, err = s.run()
        self.assertEqual(rc, 2)
        self.assertIn("no commands log", err)

    def test_a_configured_exit_codes_map_is_refused(self):
        s = self.journey_logs()
        self.reconfigure(s, exit_codes={"pwsh run-windows-controller.ps1 (typed)": 0})
        rc, summary, err = s.run()
        self.assertEqual(rc, 2)
        self.assertIn("configured exit_codes map is refused", err)

    def test_a_recorded_pass_against_the_journeys_own_failure_is_refused(self):
        s = self.journey_logs(trailer=1, recorded=0)
        rc, summary, err = s.run("--write")
        self.assertEqual(rc, 2)
        self.assertIn("trailer says exit=1", err)
        self.assertEqual(s.records(), {})

    def test_a_recorded_failure_keeps_the_row_in_progress(self):
        s = self.journey_logs(trailer=0, recorded=1)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        r = row(summary, "A24", JOURNEY_PLATFORM)
        self.assertEqual(r["status"], "in_progress", r)
        self.assertEqual(r["failed_commands"], [CONTROLLER_COMMAND])


def controller_out(d, trailer=0, recorded=0, commit="0" * 40, host="os=windows-11\n", extra=None):
    """A directory as record-windows-controller.ps1 leaves it on the PC."""
    d.mkdir(parents=True)
    (d / "tests.txt").write_text(
        f"### {JOURNEY}\n\nrunning 1 tests\ntest a24_pair ... ok\n\nsuccesses:\n\n---- a24_pair stdout ----\n"
        f"m06 observation: a24 pair: owner_enrolled=true\n\ntest result: ok. 1 passed; 0 failed; 0 ignored\n"
        f"### {JOURNEY} exit={trailer}\n")
    (d / "host.txt").write_text(host)
    (d / "commands.txt").write_text(f"exit {recorded}: {CONTROLLER_COMMAND}\n")
    (d / "build.txt").write_text(f"commit={commit}\n" + "".join(f"{n} sha256: {'c' * 64}\n" for n in IMPORTER.BUILD_NAMES))
    for name, body in (extra or {}).items():
        (d / name).write_text(body)
    return d


class ControllerImport(unittest.TestCase):
    """⟨M06 exit; RESEARCH §0 items 1, 5⟩ import-windows-controller.py: the scan before anything
    is written, the recorder's code checked against the journey's, and the configuration filled."""

    def setUp(self):
        t = tempfile.TemporaryDirectory(prefix="m06wc")
        self.addCleanup(t.cleanup)
        self.d = Path(t.name)
        self.art = self.d / "exit-x"
        self.art.mkdir()
        cfg = copy.deepcopy(RUNS)
        cfg["artifacts_root"] = str(self.art)
        cfg["platforms"][JOURNEY_PLATFORM]["exit_codes"] = {"typed": 0}
        cfg["platforms"][JOURNEY_PLATFORM]["unavailable"] = "not yet"
        self.cfg = self.art / "runs.json"
        self.cfg.write_text(json.dumps(cfg))

    def refused(self, src, why):
        with self.assertRaises(IMPORTER.Refused) as e:
            IMPORTER.import_dir(src, self.art, "0" * 40, self.cfg)
        self.assertIn(why, str(e.exception))
        self.assertFalse((self.art / JOURNEY_PLATFORM).exists())
        self.assertEqual(json.loads(self.cfg.read_text())["platforms"][JOURNEY_PLATFORM].get("unavailable"), "not yet")

    def test_an_import_copies_the_files_and_points_the_configuration_at_them(self):
        src = controller_out(self.d / "pc", extra={"ssh-stderr.txt": "Connection closed\n"})
        dest, digest, journey, recorded = IMPORTER.import_dir(src, self.art, "0" * 40, self.cfg)
        self.assertEqual((journey, recorded), (0, 0))
        self.assertEqual(sorted(p.name for p in dest.iterdir()), ["build.txt", "commands.txt", "host.txt", "ssh-stderr.txt", "tests.txt"])
        p = json.loads(self.cfg.read_text())["platforms"][JOURNEY_PLATFORM]
        self.assertNotIn("unavailable", p)
        self.assertNotIn("exit_codes", p)
        self.assertEqual(p["commands_logs"], [f"{JOURNEY_PLATFORM}/commands.txt"])
        self.assertEqual(p["artifact_digest"], digest)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(ev.parse_commands(dest / "commands.txt"), {CONTROLLER_COMMAND: 0})

    def test_a_canary_a_sid_a_home_path_or_an_address_is_refused_before_anything_is_written(self):
        for n, host in enumerate(("x=HEIMDALL_CANARY_abc\n", "sid=S-1-5-21-1-2-3\n", "p=C:\\Users\\someone\\x\n",
                                  "addr=192.168.1.7\n", "p=/Users/someone/x\n")):
            self.refused(controller_out(self.d / f"pc{n}", host=host), "carries")

    def test_a_pass_the_journey_never_reported_is_refused(self):
        self.refused(controller_out(self.d / "pc", trailer=1, recorded=0), "trailer says exit=1")

    def test_a_recorded_failure_after_the_journeys_pass_is_kept(self):
        dest, _, journey, recorded = IMPORTER.import_dir(controller_out(self.d / "pc", trailer=0, recorded=1), self.art, "0" * 40, self.cfg)
        self.assertEqual((journey, recorded), (0, 1))

    def test_another_commit_an_extra_file_a_missing_file_or_a_typed_command_is_refused(self):
        self.refused(controller_out(self.d / "a", commit="1" * 40), "another commit")
        self.refused(controller_out(self.d / "b", extra={"notes.txt": "x\n"}), "unexpected files")
        b = controller_out(self.d / "c")
        (b / "build.txt").unlink()
        self.refused(b, "missing files")
        c = controller_out(self.d / "d")
        (c / "commands.txt").write_text("exit 0: pwsh run-windows-controller.ps1 typed by hand\n")
        self.refused(c, "recorder's")

    def test_an_import_never_overwrites(self):
        IMPORTER.import_dir(controller_out(self.d / "a"), self.art, "0" * 40, self.cfg)
        with self.assertRaises(IMPORTER.Refused):
            IMPORTER.import_dir(controller_out(self.d / "b"), self.art, "0" * 40, self.cfg)


class JourneyBlocked(unittest.TestCase):
    """⟨M06 exit; RESEARCH §0 item 3⟩ A journey that printed `journey: blocked` is not a pass."""

    TARGET, TEST = "e2e_exit_m06", "a24_runner_without_controller"

    def setUp(self):
        self.index = reduced_index()
        if (self.TARGET, self.TEST) not in ev.required(self.index, INV, "groups", "A24", "linux"):
            self.skipTest("the committed inventory lacks the A24 journey")

    def blocked_line(self, why="no fixture sshd on this host"):
        return f"m06 observation: a24 journey: blocked ({why})"

    def test_a_blocked_journey_reported_ok_blocks_its_row_with_the_logged_reason(self):
        s = Scratch(self, observations={"linux": {(self.TARGET, self.TEST): [self.blocked_line()]}})
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        r = row(summary, "A24", "linux")
        self.assertEqual(r["status"], "blocked", r)
        self.assertIn("a24 journey: blocked (no fixture sshd on this host)", r["blocked_on"])
        self.assertIn(f"{self.TARGET}::{self.TEST}", r["not_run_on_this_platform"])
        self.assertEqual(row(summary, "A24", "macos")["status"], "verified")
        recs = None
        rc, _, err = s.run("--write")
        self.assertEqual(rc, 0, err)
        recs = s.records()
        self.assertIn("journey: blocked", recs["A24"]["blocked_on"])

    def test_a_failure_in_the_same_row_still_outranks_it(self):
        index = reduced_index()
        logs = passing_logs(index, INV)
        other = next((t, n) for t, n in ev.required(index, INV, "groups", "A24", "linux") if (t, n) != (self.TARGET, self.TEST))
        logs["linux"][other[0]][other[1]] = "FAILED"
        s = Scratch(self, index=index, logs=logs, observations={"linux": {(self.TARGET, self.TEST): [self.blocked_line()]}})
        rc, summary, err = s.run()
        self.assertEqual(row(summary, "A24", "linux")["status"], "in_progress")

    def test_the_line_counts_after_more_lines_than_a_row_keeps(self):
        lines = [f"m06 observation: a24 step-{i}: ok" for i in range(ev.OBSERVATION_LINES_PER_TEST + 5)]
        s = Scratch(self, observations={"linux": {(self.TARGET, self.TEST): [*lines, self.blocked_line("no fixture sshd for the fixed pair")]}})
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        r = row(summary, "A24", "linux")
        self.assertEqual(r["status"], "blocked", r)
        self.assertIn("no fixture sshd for the fixed pair", r["blocked_on"])

    def test_the_scanner_attributes_the_line_to_its_test_in_cargo_and_harness_logs(self):
        with tempfile.TemporaryDirectory(prefix="m06jb") as d:
            p = Path(d) / "x.txt"
            p.write_text(
                "     Running tests/e2e/exit_m06.rs (target/debug/deps/e2e_exit_m06-0123abcd)\nrunning 2 tests\n"
                "test a ... ok\ntest b ... ok\n\nsuccesses:\n\n---- a stdout ----\nm06 observation: a07 issued: ok\n\n"
                "---- b stdout ----\nm06 observation: t06 journey: blocked (why)\n\ntest result: ok.\n"
                "### e2e_exit_m06_iroh\n---- c stdout ----\nm06 observation: a26 journey: blocked ()\n")
            self.assertEqual(m06.scan_journey_blocked(p), {
                ("e2e_exit_m06", "b"): "t06 journey: blocked (why)",
                ("e2e_exit_m06_iroh", "c"): "a26 journey: blocked (no reason logged)",
            })


class RunIdentity(unittest.TestCase):
    """⟨M06 exit; RESEARCH §0 item 6⟩ --write refuses unfilled identity fields."""

    def test_write_refuses_each_unfilled_field_and_a_dry_run_still_evaluates(self):
        for field, value, why in (("build_commit", None, "build_commit"), ("artifact_digest", None, "artifact_digest"),
                                  ("started_at", "2026-11-22", "started_at"), ("environment", {}, "environment")):
            s = Scratch(self)
            cfg = json.loads((s.dir / "runs.json").read_text())
            cfg[field] = value
            (s.dir / "runs.json").write_text(json.dumps(cfg))
            rc, summary, err = s.run()
            self.assertEqual(rc, 0, (field, err))
            rc, summary, err = s.run("--write")
            self.assertEqual(rc, 2, field)
            self.assertIn(why, err)
            self.assertEqual(s.records(), {}, field)

    def test_write_refuses_a_platform_that_ran_without_a_digest_but_not_one_that_did_not_run(self):
        s = Scratch(self, platforms={"linux": {"artifact_digest": None}})
        rc, _, err = s.run("--write")
        self.assertEqual(rc, 2)
        self.assertIn("platforms.linux.artifact_digest", err)
        s = Scratch(self, platforms={"linux": {"artifact_digest": None, "unavailable": "the devbox", "logs": [], "commands_logs": [], "facts": []}})
        rc, _, err = s.run("--write")
        self.assertEqual(rc, 0, err)


def load_filler():
    spec = importlib.util.spec_from_file_location("fill_run_facts", HERE / "fill-run-facts.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FillRunFacts(unittest.TestCase):
    """⟨M06 exit; RESEARCH §0 item 6⟩ fill-run-facts.py, with git and the toolchain stubbed."""

    HEAD = "d" * 40

    def setUp(self):
        self.f = load_filler()
        outputs = {("git", "status"): "", ("git", "rev-parse"): self.HEAD, ("uname",): "Synthetic 1.0 arm64",
                   ("rustc",): "rustc 1.0.0", ("cargo",): "cargo 1.0.0", ("zig",): "0.0.0"}
        self.f.run = lambda *cmd, cwd=None: outputs.get(cmd[:2], outputs.get(cmd[:1]))
        t = tempfile.TemporaryDirectory(prefix="m06fill")
        self.addCleanup(t.cleanup)
        self.art = Path(t.name)
        for plat, build in (("linux", f"plain_rt sha256: {'1' * 64}\n"), ("windows-controller", f"commit={self.HEAD}\nheimdall.exe sha256: {'2' * 64}\n")):
            (self.art / plat).mkdir()
            (self.art / plat / "tests.txt").write_text("### x\n")
            (self.art / plat / "build.txt").write_text(build)
        self.bin = self.art / "heimdall-mac"
        self.bin.write_text("mac")
        self.cfg = {"artifacts_root": str(self.art), "build_commit": None, "artifact_digest": None, "started_at": None,
                    "environment": {}, "evidence_paths": [], "platforms": {
                        "linux": {"label": "linux", "logs": ["linux/tests.txt"], "artifact_digest": None},
                        "windows-controller": {"label": "wc", "logs": ["windows-controller/tests.txt"], "artifact_digest": None},
                        "macos": {"label": "mac", "logs": [], "artifact_digest": None},
                        "windows": {"label": "w", "unavailable": "the PC", "artifact_digest": None}}}

    def fill(self, started="2000-01-01T00:00:00Z", **kw):
        return self.f.fill(self.cfg, str(self.art / "runs.json"), started, bins={"macos": [("heimdall", str(self.bin))]}, **kw)

    def test_the_fields_come_from_the_inputs_and_pass_the_generators_check(self):
        new, digests, _ = self.fill(commit=self.HEAD)
        self.assertEqual(new["build_commit"], self.HEAD)
        self.assertEqual(new["started_at"], "2000-01-01T00:00:00Z")
        self.assertEqual(new["artifact_digest"], hashlib.sha256(digests.encode()).hexdigest())
        self.assertIn(f"linux plain_rt sha256: {'1' * 64}", digests)
        self.assertIn(f"macos heimdall sha256: {hashlib.sha256(b'mac').hexdigest()}", digests)
        self.assertEqual(m06.identity_problems(new), [])
        self.assertIsNone(new["platforms"]["windows"]["artifact_digest"], "a platform that did not run gets no digest")
        self.assertEqual(new["environment"]["build_host"]["uname"], "Synthetic 1.0 arm64")
        self.assertIsNone(self.cfg["build_commit"], "the input configuration is not changed")

    def test_an_existing_platform_digest_is_kept(self):
        self.cfg["platforms"]["linux"]["artifact_digest"] = "e" * 64
        new, _, _ = self.fill()
        self.assertEqual(new["platforms"]["linux"]["artifact_digest"], "e" * 64)

    def test_refusals(self):
        with self.assertRaises(self.f.Refused):
            self.fill(commit="f" * 40)
        with self.assertRaises(self.f.Refused):
            self.fill(started="2026-11-23")
        with self.assertRaises(self.f.Refused):
            self.fill(started="2999-01-01T00:00:00Z")
        (self.art / "windows-controller" / "build.txt").write_text(f"commit={'9' * 40}\nheimdall.exe sha256: {'2' * 64}\n")
        with self.assertRaises(self.f.Refused):
            self.fill()
        (self.art / "windows-controller" / "build.txt").write_text("nothing\n")
        with self.assertRaises(self.f.Refused):
            self.fill()
        self.f.run = lambda *cmd, cwd=None: " M tracked.rs" if cmd[:2] == ("git", "status") else self.HEAD
        with self.assertRaises(self.f.Refused):
            self.fill()


class FillRunFactsRunCommit(unittest.TestCase):
    """⟨M06 exit C10b⟩ fill-run-facts.py's per-platform run_commit, against a scratch git
    repository (never this repository's history); only the toolchain is stubbed."""

    def git(self, *args):
        return subprocess.run(("git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
                               "-c", "commit.gpgsign=false", *args), cwd=self.repo, capture_output=True, text=True,
                              check=True).stdout.strip()

    def commit(self, files, msg):
        for rel, text in files.items():
            (self.repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / rel).write_text(text)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", msg)
        return self.git("rev-parse", "HEAD")

    def setUp(self):
        env = mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})
        env.start()
        self.addCleanup(env.stop)
        self.f = load_filler()
        real = self.f.run
        stub = {("uname",): "Synthetic 1.0 arm64", ("rustc",): "rustc 1.0.0", ("cargo",): "cargo 1.0.0", ("zig",): "0.0.0"}
        self.f.run = lambda *cmd, cwd=None: real(*cmd, cwd=cwd) if cmd[0] == "git" else stub[cmd[:1]]
        t = tempfile.TemporaryDirectory(prefix="m06runcommit")
        self.addCleanup(t.cleanup)
        self.repo = Path(t.name) / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.base = self.commit({"crates/app/src/lib.rs": "a\n", "crates/testkit/src/lib.rs": "t\n", "tests/x.rs": "x\n"}, "base")
        self.git("checkout", "-q", "-b", "side")
        self.side = self.commit({"crates/app/src/side.rs": "s\n"}, "side")
        self.git("checkout", "-q", "main")
        # testkit and tests only: no product drift from here to HEAD.
        self.quiet = self.commit({"crates/testkit/src/lib.rs": "t2\n", "tests/x.rs": "x2\n"}, "tests only")
        self.head = self.commit({"crates/app/src/lib.rs": "a2\n"}, "product")
        self.art = Path(t.name) / "art"
        (self.art / "windows-controller").mkdir(parents=True)
        (self.art / "windows-controller" / "tests.txt").write_text("### x\n")
        self.cfg = {"artifacts_root": str(self.art), "build_commit": None, "artifact_digest": None, "started_at": None,
                    "environment": {}, "evidence_paths": [], "platforms": {
                        "windows-controller": {"label": "wc", "logs": ["windows-controller/tests.txt"], "artifact_digest": None}}}

    def names(self, commit):
        (self.art / "windows-controller" / "build.txt").write_text(f"commit={commit}\nheimdall.exe sha256: {'2' * 64}\n")

    def plat(self, **kw):
        self.cfg["platforms"]["windows-controller"].update(kw)

    def fill(self):
        return self.f.fill(self.cfg, str(self.art / "runs.json"), "2000-01-01T00:00:00Z", repo=self.repo)

    def refused(self, needle):
        with self.assertRaises(self.f.Refused) as cm:
            self.fill()
        self.assertIn(needle, str(cm.exception))

    def test_default_without_run_commit_the_outputs_name_head(self):
        self.names(self.head)
        new, _, _ = self.fill()
        self.assertEqual(new["build_commit"], self.head)
        self.assertEqual(new["platforms"]["windows-controller"]["label"], "wc")
        self.assertNotIn("run_commit_drift", new["platforms"]["windows-controller"])
        self.names(self.quiet)
        self.refused(f"not HEAD {self.head}")

    def test_an_output_naming_another_commit_than_run_commit_is_refused(self):
        self.names(self.head)
        self.plat(run_commit=self.quiet, run_commit_reason="built before the product commit",
                  run_commit_drift_allow=["crates/app/src/lib.rs"])
        self.refused(f"not its run_commit {self.quiet}")

    def test_a_run_commit_that_is_not_an_ancestor_of_head_is_refused(self):
        self.names(self.side)
        self.plat(run_commit=self.side, run_commit_reason="a side branch")
        self.refused("is not an ancestor of HEAD")

    def test_a_run_commit_other_than_head_needs_a_reason(self):
        self.names(self.quiet)
        self.plat(run_commit=self.quiet)
        self.refused("run_commit_reason is missing or empty")
        self.plat(run_commit_reason="  ")
        self.refused("run_commit_reason is missing or empty")

    def test_product_drift_not_allowed_is_refused_and_testkit_and_tests_never_count(self):
        self.names(self.base)
        self.plat(run_commit=self.base, run_commit_reason="the PC ran the earlier build")
        self.refused("not in run_commit_drift_allow: crates/app/src/lib.rs")
        self.plat(run_commit_drift_allow=["crates/app/src/lib.rs", "crates/app/src/other.rs"])
        self.refused("did not change")

    def test_allowed_drift_passes_and_reaches_the_label(self):
        self.names(self.base)
        self.plat(run_commit=self.base, run_commit_reason="the PC ran the earlier build",
                  run_commit_drift_allow=["crates/app/src/lib.rs"])
        new, _, _ = self.fill()
        p = new["platforms"]["windows-controller"]
        self.assertEqual(p["run_commit_drift"], {"range": f"{self.base}..{self.head}", "count": 1, "files": ["crates/app/src/lib.rs"]})
        want = f"wc; ran at {self.base[:8]} (the PC ran the earlier build; product drift 1 files {self.base[:8]}..{self.head[:8]})"
        self.assertEqual(p["label"], want)
        self.assertEqual(new["environment"]["platforms"]["windows-controller"], want)
        self.assertEqual(new["build_commit"], self.head)
        again, _, _ = self.f.fill(new, str(self.art / "runs.json"), "2000-01-01T00:00:00Z", repo=self.repo)
        self.assertEqual(again["platforms"]["windows-controller"]["label"], want, "a second fill does not repeat the suffix")

    def test_a_platform_whose_outputs_name_no_commit_still_gets_the_checks(self):
        (self.art / "windows-controller" / "build.txt").write_text(f"heimdall.exe sha256: {'2' * 64}\n")
        self.plat(run_commit=self.quiet)
        self.refused("run_commit_reason is missing or empty")
        self.plat(run_commit_reason="tests-only commits since")
        self.head = self.commit({"tests/x.rs": "x3\n"}, "tests only again")
        self.plat(run_commit=self.git("rev-parse", "HEAD~1"))
        new, _, _ = self.fill()
        self.assertEqual(new["platforms"]["windows-controller"]["run_commit_drift"]["count"], 0)
        self.assertIn("product drift 0 files", new["platforms"]["windows-controller"]["label"])


class SkipTargetsAndFiles(unittest.TestCase):
    def test_skip_drops_exactly_the_named_targets_and_the_platform_required_maps_it_empties(self):
        reduced = m06.m05.drop_targets(copy.deepcopy(INDEX), {"e2e_exit_m06", "e2e_exit_m06_iroh"})
        for sec in reduced["groups"].values():
            self.assertNotIn("e2e_exit_m06", sec["tests"])
            self.assertNotIn("e2e_exit_m06_iroh", sec["tests"])
            # ⟨M06 W5h⟩ What is left of a platform_required map names the journey only.
            for per in (sec.get("platform_required") or {}).values():
                self.assertTrue(set(per) <= {JOURNEY, CROSSHOST}, per)
        self.assertIn("integration_transport_supervise_m06", reduced["groups"]["A26"]["tests"])
        self.assertNotIn("e2e_exit_m06", reduced["observation_targets"])
        self.assertEqual(ev.check_index(reduced), [])
        # A platform_required map that still names a kept target stays.
        kept = m06.m05.drop_targets(copy.deepcopy(INDEX), {"e2e_exit_m06_iroh"})
        self.assertEqual(kept["groups"]["A24"]["platform_required"], INDEX["groups"]["A24"]["platform_required"])
        self.assertIn("e2e_exit_m06", INDEX["groups"]["A24"]["tests"], "the input is not modified when the caller copies it")
        # ⟨M06 W5h⟩ Dropping the journey empties the maps that name only it.
        without = m06.m05.drop_targets(copy.deepcopy(INDEX), {JOURNEY, CROSSHOST})
        for sid in ("A24", "T06"):
            self.assertNotIn("platform_required", without["groups"][sid])
            self.assertNotIn(JOURNEY, without["groups"][sid]["tests"])
            self.assertNotIn(CROSSHOST, without["groups"][sid]["tests"])
        # ⟨M06 W5g⟩ Dropping one scenario keeps the other's map.
        one = m06.m05.drop_targets(copy.deepcopy(INDEX), {JOURNEY})
        self.assertEqual(set(one["groups"]["A24"]["platform_required"]), {CROSSHOST_PLATFORM})

    def test_the_transport_crates_unit_tests_are_listed_from_the_iroh_feature_build(self):
        where = ev.cargo_targets(ROOT)
        self.assertEqual(where["heimdall_transport_iroh-unit"], ("heimdall-transport-iroh", ["--lib", "--features", "iroh"]))
        self.assertEqual(where["heimdall_testkit-unit"][1], ["--lib"], "no other unit target is selected with a feature")
        self.assertEqual(INDEX["groups"]["A26"]["tests"]["heimdall_transport_iroh-unit"], "*")

    def test_write_refuses_while_a_target_is_skipped(self):
        env = dict(os.environ, HM_SKIP_TARGETS="e2e_exit_m06")
        r = subprocess.run(
            [sys.executable, "-I", str(HERE / "m06-evidence.py"), "--config", str(HERE / "runs.json"), "--write"],
            capture_output=True, text=True, env=env, cwd=ROOT,
        )
        self.assertEqual(r.returncode, 2)
        self.assertIn("never written from a reduced case index", r.stderr)

    def test_the_committed_files_agree_with_one_another(self):
        self.assertEqual(set(RUNS["records"]), set(INDEX["groups"]) | set(INDEX["exit_claims"]))
        self.assertEqual(ev.check_index(INDEX), [])
        self.assertEqual(ev.check_inventory(reduced_index(), INV), [])
        for sid, rec in RUNS["records"].items():
            self.assertTrue(rec["path"].startswith("tests/evidence/m06-"), sid)
        self.assertEqual(set(INDEX["exit_claims"][EXIT_KEY]["groups"]), set(INDEX["groups"]))
        self.assertEqual(set(RUNS["platforms"]), set(INDEX["platforms"]))
        self.assertIn("macos/features.txt", RUNS["platforms"]["macos"]["logs"], "the macOS iroh-feature pass is a configured log")
        self.assertEqual(RUNS["build_commit"], None, "runs.json is a template: no native run has happened")

    def test_the_exit_journeys_and_the_iroh_targets_are_indexed_under_their_cases(self):
        want = {
            "A24": ("e2e_exit_m06", "a24_runner_without_controller"),
            "A25": ("e2e_exit_m06", "a25_roles_invitations_decisions"),
            "A26": ("e2e_exit_m06_iroh", "a26_iroh_routes_trust"),
            "A07": ("e2e_exit_m06", "a07_runner_disconnected"),
            "T06": ("e2e_exit_m06", "t06_second_controller"),
        }
        for sid, (target, name) in want.items():
            self.assertIn(name, INDEX["groups"][sid]["tests"][target], sid)
        # ⟨M06 exit; RESEARCH §2⟩ Every test of the two exit targets is required by a case.
        indexed = {(t, n) for sec in INDEX["groups"].values() for t, ns in sec["tests"].items()
                   if t in ("e2e_exit_m06", "e2e_exit_m06_iroh") for n in ns}
        for target, path in (("e2e_exit_m06", "tests/e2e/exit_m06.rs"), ("e2e_exit_m06_iroh", "tests/e2e/exit_m06_iroh.rs")):
            names = ev.re.findall(r"#\[test\]\s*\nfn ([a-z0-9_]+)\(", (ROOT / path).read_text(encoding="utf-8"))
            self.assertTrue(names, path)
            for n in names:
                self.assertIn((target, n), indexed, f"{target}::{n} is required by no case")
        self.assertEqual(INDEX["groups"]["A26"]["tests"]["integration_transport_supervise_m06"], "*")
        # The observation pass is a default-feature `cargo test --workspace --test <t>`: it cannot name
        # a target that requires a feature (the feature pass runs those with --show-output itself).
        self.assertFalse(set(INDEX["observation_targets"]) & set(IROH_TARGETS))


if __name__ == "__main__":
    unittest.main(verbosity=1)
