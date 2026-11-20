#!/usr/bin/env python3
"""M05-U10: generator dry runs over synthetic logs, run by tests/native/m05/selftest.sh.

Reaches no host and builds nothing. The real case index (tests/native/m05/case-index.json) and the
committed required inventory (tests/native/m05/required-inventory.json) are the inputs; every log
is synthesized from them in a temporary directory, so a run here proves what the generator does
with *this* index, not with a toy one. The inventory is re-stamped with the temporary sources'
digest (the committed one is bound to the commit it was generated at), and the case index is
reduced to the targets the committed inventory holds (m05-evidence.py HM_SKIP_TARGETS semantics:
at a commit that lacks the W4 targets the index names more than the inventory resolved).

What is pinned:
  * a run in which every required test passes: every platform row of every case is verified,
    the owner-input rows (B2, B7, B9, B12) keep their cases blocked with the input named, the
    rows M04's exit closes (Q9) are deferred_with_decision and never count, and the records the
    generator writes validate against tests/evidence/record.schema.json;
  * a failed test: only that platform's row is in_progress, and the exit claim cannot be verified;
  * a missing platform: its rows are blocked with the input named, never failed or verified;
  * a Unix-only test (`platform_only` with a rationale) is excluded on Windows with the rationale
    on record and does not stop the Windows row from being verified; the same test with its
    rationale removed keeps the row in_progress (R1);
  * a test that ran but is not in the inventory is an error (ran_not_in_inventory), and a
    platform_only entry for a test that did run is stale (exit 1);
  * the WSL scenario row is read from the harness's `### wsl_hook_m05` lines: a missing step keeps
    the row in_progress;
  * HM_SKIP_TARGETS drops exactly the named targets, and --write refuses to run with it set.
"""

import copy
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def load_m05():
    argv = sys.argv
    spec = importlib.util.spec_from_file_location("m05_evidence", HERE / "m05-evidence.py")
    mod = importlib.util.module_from_spec(spec)
    sys.argv = ["m05-evidence.py"]
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.argv = argv
    return mod


m05 = load_m05()
ev = m05.ev
INDEX = json.loads((HERE / "case-index.json").read_text(encoding="utf-8"))
INV = json.loads((HERE / "required-inventory.json").read_text(encoding="utf-8"))
RUNS = json.loads((HERE / "runs.json").read_text(encoding="utf-8"))

PLATFORMS = ("macos", "linux", "windows", "wsl-distro")
GROUPS = list(INDEX["groups"])
EXIT_KEY = next(iter(INDEX["exit_claims"]))


def inventory_targets():
    out = set()
    for kind in ("groups", "exit_claims"):
        for sec in INV[kind].values():
            out.update(sec["tests"])
    return out


def reduced_index():
    """The case index without the targets the committed inventory lacks."""
    have = inventory_targets()
    scenario = set(INDEX.get("scenario_targets", {}))
    named = set()
    for kind in ("groups", "exit_claims"):
        for sec in INDEX[kind].values():
            named.update(sec.get("tests", {}))
    skip = {t for t in named if t not in have and t not in scenario}
    return m05.drop_targets(copy.deepcopy(INDEX), skip)


def log_text(targets, style):
    lines = []
    for target, tests in targets.items():
        if style == "cargo":
            if target.endswith("-unit"):
                crate = target[: -len("-unit")]
                lines.append(f"     Running unittests src/lib.rs (target/debug/deps/{crate}-0123abcd)")
            else:
                lines.append(f"     Running tests/x/{target}.rs (target/debug/deps/{target}-0123abcd)")
        else:
            lines.append(f"### {target}")
        lines.append(f"running {len(tests)} tests")
        for name, result in tests.items():
            lines.append(f"test {name} ... {result}")
        if style != "cargo":
            lines.append(f"### {target} exit=0")
    return "\n".join(lines) + "\n"


def passing_logs(index, inv):
    """{platform: {target: {test: result}}}: every test the index requires on that platform
    passes (what a clean native run would print)."""
    logs = {}
    for plat in PLATFORMS:
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

    def __init__(self, testcase, index=None, logs=None, platforms=None, inv=None):
        self.tmp = tempfile.TemporaryDirectory(prefix="m05ev")
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
            artifact_digest="n/a",
            started_at="2026-11-18T00:00:00+00:00",
            commands=["synthetic"],
            evidence_paths=["synthetic"],
        )
        for pname in PLATFORMS:
            style = "cargo" if pname == "macos" else "harness"
            (d / f"{pname}.log").write_text(log_text(self.logs.get(pname, {}), style))
            (d / f"{pname}.commands").write_text("exit 0: the required command\n")
            (d / f"{pname}.facts").write_text("os=synthetic\nshell-zsh=zsh 5.9 (synthetic)\nsecret-thing=must not be kept\n")
            cfg["platforms"][pname].update(
                logs=[f"{pname}.log"], commands_logs=[f"{pname}.commands"], facts=[f"{pname}.facts"],
                artifact_digest="n/a",
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
    """Every row of the exit claim on a platform (one per case it is made of)."""
    label = RUNS["platforms"][plat]["label"]
    found = [r for r in rows(summary, "exit_claims", EXIT_KEY) if r["platform"] == label]
    assert found, plat
    return found




class CleanRun(unittest.TestCase):
    def test_every_required_test_passing_verifies_every_platform_row_and_blocks_on_the_owner_inputs(self):
        s = Scratch(self)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        for sid in GROUPS:
            for plat in PLATFORMS:
                if plat not in INDEX["groups"][sid]["declared_platforms"]:
                    continue
                self.assertEqual(row(summary, sid, plat)["status"], "verified", (sid, plat))
        for plat in PLATFORMS:
            self.assertEqual({r["status"] for r in claim_rows(summary, plat)}, {"verified"}, plat)
        # The lowest-row rule: the owner-input rows keep each case blocked and name the input.
        blocked = {sid: summary["groups"][sid]["status"] for sid in GROUPS}
        self.assertEqual(set(blocked.values()), {"blocked"}, blocked)
        self.assertEqual(summary["exit_claims"][EXIT_KEY]["status"], "blocked")
        on = {}
        for sid in GROUPS:
            on[sid] = " ".join(r.get("blocked_on", "") for r in rows(summary, "groups", sid) if r["status"] == "blocked")
        self.assertIn("B7", on["A02"])
        self.assertIn("B12", on["A02"])
        self.assertIn("B2", on["A29"])
        for sid in GROUPS:
            self.assertIn("B9", on[sid], sid)

    def test_the_rows_that_m04_closes_are_deferred_and_never_counted(self):
        s = Scratch(self)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        for sid in ("A16", "A28"):
            deferred = [r for r in rows(summary, "groups", sid) if r["status"] == "deferred_with_decision"]
            self.assertTrue(deferred, sid)
            self.assertTrue(all("Q9" in r.get("decision", "") for r in deferred), sid)

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
        self.assertIn("B2", recs["A29"]["blocked_on"])
        self.assertEqual(recs[EXIT_KEY]["case_id"], "m05-exit-claims")
        self.assertEqual(recs["A02"]["case_id"], "A02")


class FailuresAndGaps(unittest.TestCase):
    def test_a_failed_test_keeps_only_its_platform_row_in_progress(self):
        index = reduced_index()
        logs = passing_logs(index, INV)
        logs["macos"]["e2e_context_m05"]["a04_edits_branches_and_added_destination"] = "FAILED"
        s = Scratch(self, index=index, logs=logs)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        self.assertEqual(row(summary, "A04", "macos")["status"], "in_progress")
        self.assertIn("e2e_context_m05::a04_edits_branches_and_added_destination", " ".join(row(summary, "A04", "macos")["failed"]))
        self.assertEqual(row(summary, "A04", "linux")["status"], "verified")
        # The exit claim is made of the cases' rows: its macOS rows are not all verified, Linux's are.
        self.assertIn("in_progress", {r["status"] for r in claim_rows(summary, "macos")})
        self.assertEqual({r["status"] for r in claim_rows(summary, "linux")}, {"verified"})
        # The lowest-row rule (blocked < in_progress): the B9 row still decides the case's status, but
        # the failed row is on record and the Linux and Windows rows are unaffected.
        self.assertEqual(summary["groups"]["A04"]["status"], "blocked")
        self.assertEqual(row(summary, "A04", "windows")["status"], "verified")

    def test_a_missing_platform_is_blocked_with_the_input_named(self):
        index = reduced_index()
        logs = passing_logs(index, INV)
        logs["windows"] = {}
        reason = "the Windows PC is not reachable (synthetic)"
        s = Scratch(self, index=index, logs=logs, platforms={"windows": {"unavailable": reason}})
        rc, summary, err = s.run()
        for sid in GROUPS:
            r = row(summary, sid, "windows")
            self.assertEqual(r["status"], "blocked", sid)
            self.assertEqual(r["blocked_on"], reason, sid)
            self.assertEqual(row(summary, sid, "macos")["status"], "verified", sid)
        self.assertEqual({r["status"] for r in claim_rows(summary, "windows")}, {"blocked"})

    def test_an_ignored_required_test_is_never_a_pass(self):
        index = reduced_index()
        logs = passing_logs(index, INV)
        logs["linux"]["model_decision_budget"]["p10_trust_cooldown_no_record_until_owner_asks"] = "ignored"
        s = Scratch(self, index=index, logs=logs)
        rc, summary, err = s.run()
        self.assertEqual(row(summary, "A02", "linux")["status"], "in_progress")
        self.assertEqual(row(summary, "A04", "linux")["status"], "in_progress")
        self.assertEqual(row(summary, "A04", "macos")["status"], "verified")

    def test_a_test_that_ran_but_is_not_in_the_inventory_is_an_error(self):
        index = reduced_index()
        logs = passing_logs(index, INV)
        # model_decision_budget is a whole-target ("*") spec of A02 and A04.
        logs["linux"]["model_decision_budget"]["p10_a_test_nobody_indexed"] = "ok"
        s = Scratch(self, index=index, logs=logs)
        rc, summary, err = s.run()
        self.assertEqual(rc, 1, "ran_not_in_inventory must not pass silently")
        self.assertIn("model_decision_budget::p10_a_test_nobody_indexed", err)
        self.assertEqual(row(summary, "A02", "linux")["status"], "in_progress")
        self.assertEqual(row(summary, "A02", "macos")["status"], "verified")

    def test_a_wsl_step_that_did_not_run_keeps_the_wsl_row_in_progress(self):
        index = reduced_index()
        logs = passing_logs(index, INV)
        del logs["wsl-distro"]["wsl_hook_m05"]["m05_wsl_hook_never_evaluates_repository_text"]
        s = Scratch(self, index=index, logs=logs)
        rc, summary, err = s.run()
        self.assertEqual(row(summary, "A02", "wsl-distro")["status"], "in_progress")
        self.assertEqual(row(summary, "A29", "wsl-distro")["status"], "in_progress")
        self.assertEqual(row(summary, "A02", "windows")["status"], "verified")

    def test_a_wsl_step_that_failed_is_in_progress_not_blocked(self):
        index = reduced_index()
        logs = passing_logs(index, INV)
        logs["wsl-distro"]["wsl_hook_m05"]["m05_wsl_bash_and_zsh_present"] = "FAILED"
        s = Scratch(self, index=index, logs=logs)
        rc, summary, err = s.run()
        self.assertEqual(row(summary, "A02", "wsl-distro")["status"], "in_progress")


class PlatformOnly(unittest.TestCase):
    # A Unix-only journey that exists in the committed inventory and carries a rationale.
    TARGET, NAME = "e2e_hook_m05", "hook_warms_the_default_so_the_first_ordinary_ssh_logs_in"

    def test_a_unix_only_test_is_excluded_on_windows_with_its_rationale_and_the_row_is_verified(self):
        s = Scratch(self)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        w = row(summary, "A02", "windows")
        self.assertEqual(w["status"], "verified")
        self.assertGreater(w["excluded_on_this_platform"], 0)
        self.assertIn(f"{self.TARGET}::{self.NAME}", w.get("excluded_by_rationale", {}), "the exclusion carries its case-index rationale")
        self.assertFalse(w.get("excluded_without_rationale"))
        self.assertNotIn(self.NAME, s.logs["windows"].get(self.TARGET, {}))
        self.assertIn(self.NAME, s.logs["macos"][self.TARGET])

    def test_the_same_exclusion_without_a_rationale_keeps_the_row_in_progress(self):
        index = reduced_index()
        key = f"{self.TARGET}::{self.NAME}"
        self.assertIn(key, index["platform_only"])
        del index["platform_only"][key]
        logs = passing_logs(index, INV)
        s = Scratch(self, index=index, logs=logs)
        rc, summary, err = s.run()
        w = row(summary, "A02", "windows")
        self.assertEqual(w["status"], "in_progress")
        self.assertIn(f"{self.TARGET}::{self.NAME}", w["excluded_without_rationale"])
        self.assertEqual(row(summary, "A02", "macos")["status"], "verified")

    def test_a_rationale_for_a_test_that_ran_is_stale(self):
        index = reduced_index()
        logs = passing_logs(index, INV)
        logs["windows"].setdefault(self.TARGET, {})[self.NAME] = "ok"
        s = Scratch(self, index=index, logs=logs)
        rc, summary, err = s.run()
        self.assertEqual(rc, 1, "platform_only_stale is an error")

    def test_every_platform_only_entry_of_the_index_has_a_one_line_rationale(self):
        for key, entry in INDEX["platform_only"].items():
            self.assertTrue(entry["rationale"].strip(), key)
            self.assertNotIn("\n", entry["rationale"], key)
            self.assertTrue(set(entry["platforms"]) <= {"macos", "linux", "windows"}, key)


class SkipTargets(unittest.TestCase):
    def test_skip_drops_exactly_the_named_targets_everywhere(self):
        reduced = m05.drop_targets(copy.deepcopy(INDEX), {"e2e_exit_m05", "adversarial_prompt_injection"})
        for kind in ("groups", "exit_claims"):
            for sec in reduced[kind].values():
                self.assertNotIn("e2e_exit_m05", sec.get("tests", {}))
                self.assertNotIn("adversarial_prompt_injection", sec.get("tests", {}))
        self.assertIn("adversarial_prompt_injection_cli", reduced["groups"]["A29"]["tests"])
        self.assertIn("e2e_context_m05", reduced["groups"]["A02"]["tests"])
        self.assertNotIn("e2e_exit_m05", reduced["observation_targets"])
        # The input is not modified in place when the caller copies it.
        self.assertIn("e2e_exit_m05", INDEX["groups"]["A02"]["tests"])

    def test_write_refuses_while_a_target_is_skipped(self):
        env = dict(os.environ, HM_SKIP_TARGETS="e2e_exit_m05")
        r = subprocess.run(
            [sys.executable, "-I", str(HERE / "m05-evidence.py"), "--config", str(HERE / "runs.json"), "--write"],
            capture_output=True, text=True, env=env, cwd=ROOT,
        )
        self.assertEqual(r.returncode, 2)
        self.assertIn("never written from a reduced case index", r.stderr)

    def test_the_committed_files_agree_with_one_another(self):
        self.assertEqual(set(RUNS["records"]), set(INDEX["groups"]) | set(INDEX["exit_claims"]))
        self.assertEqual(ev.check_index(INDEX), [])
        for sid, rec in RUNS["records"].items():
            self.assertTrue(rec["path"].startswith("tests/evidence/m05-"), sid)
        self.assertEqual(set(INDEX["exit_claims"][EXIT_KEY]["groups"]), set(INDEX["groups"]))
        # Records whose text names a B-ID must name one the plan defines.
        text = json.dumps(INDEX)
        for b in ("B2", "B7", "B9", "B12"):
            self.assertIn(b, text)
        self.assertEqual(RUNS["build_commit"], None, "runs.json is a template: no native run has happened")


if __name__ == "__main__":
    unittest.main(verbosity=1)
