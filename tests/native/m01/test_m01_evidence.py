#!/usr/bin/env python3
"""Self-test for m01-evidence.py (review findings C02, C03).

Run from the repository root:  python3 -I tests/native/m01/test_m01_evidence.py

Everything is synthetic and lives in a temporary directory, except
`test_real_a19_without_the_contracts_target_is_not_verified`, which reads the
committed case index, required inventory and saved macOS log (read-only) and
removes the whole `contracts` target from the parsed log in memory.

C02: the expected inventory is the committed required inventory, never the run
logs; a wildcard target that is missing from the logs leaves its tests absent,
so the row cannot be verified; an empty or missing wildcard inventory is an
error.
C03: a required command's nonzero exit prevents `verified`; an intentionally
failing negative probe is recorded separately and must fail as expected.
"""

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
_spec = importlib.util.spec_from_file_location("m01_evidence", HERE / "m01-evidence.py")
ev = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ev)


def log_text(targets):
    """A cargo-style log: {target: {name: result}}."""
    lines = []
    for target, tests in targets.items():
        lines.append(f"     Running ../../tests/x/{target}.rs (target/debug/deps/{target}-0123abcd)")
        lines.append(f"running {len(tests)} tests")
        for name, result in tests.items():
            lines.append(f"test {name} ... {result}")
    return "\n".join(lines) + "\n"


INDEX = {
    "description": "synthetic",
    "groups": {
        "G1": {
            "title": "synthetic group",
            "requirement_ids": [],
            "tests": {"explicit_t": ["e1", "e2"], "wild_t": "*"},
        }
    },
    "exit_claims": {"claim": {"groups": ["G1"]}},
}
INVENTORY = {
    "groups": {"G1": {"tests": {"explicit_t": ["e1", "e2"], "wild_t": ["w1", "w2", "w3"]}}},
    "exit_claims": {},
}
FULL = {
    "explicit_t": {"e1": "ok", "e2": "ok"},
    "wild_t": {"w1": "ok", "w2": "ok", "w3": "ok"},
}


class Scratch:
    """A temporary index, inventory, logs and config; runs main()."""

    def __init__(self, testcase, logs, index=INDEX, inventory=INVENTORY, platform=None):
        self.tmp = tempfile.TemporaryDirectory(prefix="m01ev")
        testcase.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        (d / "case-index.json").write_text(json.dumps(index))
        if inventory is not None:
            (d / "required-inventory.json").write_text(json.dumps(inventory))
        (d / "run.txt").write_text(log_text(logs))
        p = {
            "label": "synthetic-host",
            "logs": [str(d / "run.txt")],
            "exit_codes": {"check.sh": 0},
            "artifact_digest": "n/a",
        }
        p.update(platform or {})
        self.cfg = {
            "case_index": str(d / "case-index.json"),
            "summary_out": str(d / "summary.json"),
            "platforms": {"macos": p},
        }
        (d / "runs.json").write_text(json.dumps(self.cfg))
        self.dir = d

    def run(self):
        out, err = io.StringIO(), io.StringIO()
        argv = sys.argv
        sys.argv = ["m01-evidence.py", "--config", str(self.dir / "runs.json")]
        try:
            with redirect_stdout(out), redirect_stderr(err):
                try:
                    rc = ev.main()
                except SystemExit as e:
                    rc = e.code
        finally:
            sys.argv = argv
        summary_path = self.dir / "summary.json"
        summary = json.loads(summary_path.read_text()) if summary_path.exists() else None
        return rc, summary, err.getvalue()


def statuses(summary, gid="G1"):
    return [r["status"] for r in summary["groups"][gid]["rows"]]


class C02Inventory(unittest.TestCase):
    def test_complete_logs_verify(self):
        rc, summary, err = Scratch(self, FULL).run()
        self.assertEqual(rc, 0, err)
        self.assertEqual(statuses(summary), ["verified"])
        self.assertEqual(summary["groups"]["G1"]["tests"], 5)

    def test_removing_a_whole_wildcard_target_cannot_verify(self):
        logs = {"explicit_t": FULL["explicit_t"]}
        rc, summary, err = Scratch(self, logs).run()
        self.assertNotEqual(rc, 0, "a required target that never ran is an error")
        self.assertIsNotNone(summary)
        self.assertEqual(summary["groups"]["G1"]["tests"], 5, "the inventory, not the logs")
        row = summary["groups"]["G1"]["rows"][0]
        self.assertNotEqual(row["status"], "verified")
        self.assertIn("wild_t", row.get("missing_targets", []))
        claim = summary["exit_claims"]["claim"]["rows"][0]
        self.assertNotEqual(claim["status"], "verified")

    def test_dropping_one_wildcard_test_cannot_verify(self):
        logs = {"explicit_t": FULL["explicit_t"], "wild_t": {"w1": "ok", "w2": "ok"}}
        rc, summary, err = Scratch(self, logs).run()
        self.assertNotEqual(statuses(summary), ["verified"])
        self.assertNotEqual(rc, 0, err)

    def test_an_empty_wildcard_inventory_is_rejected(self):
        inv = json.loads(json.dumps(INVENTORY))
        inv["groups"]["G1"]["tests"]["wild_t"] = []
        rc, summary, err = Scratch(self, FULL, inventory=inv).run()
        self.assertNotEqual(rc, 0)
        self.assertIn("wild_t", err)
        if summary is not None:
            self.assertNotIn("verified", statuses(summary))

    def test_a_missing_inventory_is_rejected(self):
        rc, summary, err = Scratch(self, FULL, inventory=None).run()
        self.assertNotEqual(rc, 0)
        self.assertIsNone(summary, "nothing is written without the required inventory")

    def test_inventory_drift_from_the_index_is_rejected(self):
        inv = json.loads(json.dumps(INVENTORY))
        inv["groups"]["G1"]["tests"]["explicit_t"] = ["e1"]
        rc, _, err = Scratch(self, FULL, inventory=inv).run()
        self.assertNotEqual(rc, 0)
        self.assertIn("explicit_t", err)
        inv = json.loads(json.dumps(INVENTORY))
        del inv["groups"]["G1"]["tests"]["wild_t"]
        rc, _, err = Scratch(self, FULL, inventory=inv).run()
        self.assertNotEqual(rc, 0)
        self.assertIn("wild_t", err)

    def test_a_new_test_outside_the_inventory_needs_regeneration(self):
        logs = json.loads(json.dumps(FULL))
        logs["wild_t"]["w4"] = "ok"
        rc, _, err = Scratch(self, logs).run()
        self.assertNotEqual(rc, 0)
        self.assertIn("w4", err)

    def test_generation_refuses_a_wildcard_target_with_zero_tests(self):
        listing = {"explicit_t": ["e1", "e2", "other"], "wild_t": ["w2", "w1"]}
        inv = ev.build_inventory(INDEX, listing.get)
        self.assertEqual(inv["groups"]["G1"]["tests"]["wild_t"], ["w1", "w2"])
        self.assertEqual(inv["groups"]["G1"]["tests"]["explicit_t"], ["e1", "e2"])
        with self.assertRaises(ev.InventoryError):
            ev.build_inventory(INDEX, {"explicit_t": ["e1", "e2"], "wild_t": []}.get)
        with self.assertRaises(ev.InventoryError):
            ev.build_inventory(INDEX, {"explicit_t": ["e1", "e2"]}.get)
        # An explicitly indexed name the sources do not define is a defect too.
        with self.assertRaises(ev.InventoryError):
            ev.build_inventory(INDEX, {"explicit_t": ["e1"], "wild_t": ["w1"]}.get)

    def test_real_a19_without_the_contracts_target_is_not_verified(self):
        cfg = json.loads((HERE / "runs.json").read_text())
        index = json.loads((ROOT / cfg["case_index"]).read_text())
        inventory = json.loads((HERE / "required-inventory.json").read_text())
        log = ROOT / cfg["platforms"]["macos"]["logs"][0]
        logs = ev.parse_log(log)
        self.assertGreater(len(logs.get("contracts", {})), 0, "the saved log ran contracts")
        del logs["contracts"]
        problems = ev.check_inventory(index, inventory)
        self.assertEqual(problems, [], problems)
        tests = ev.expand_required(index["groups"]["A19"]["tests"], inventory["groups"]["A19"]["tests"])
        self.assertTrue(any(t == "contracts" for t, _ in tests))
        pconf = dict(cfg["platforms"]["macos"])
        row = ev.row_for("macos", pconf, logs, tests, [], index["groups"]["A19"])
        self.assertNotEqual(row["status"], "verified")
        self.assertIn("contracts", row.get("missing_targets", []))


class C03Exits(unittest.TestCase):
    TESTS = [("t", "a")]
    LOGS = {"t": {"a": "ok"}}

    def row(self, **pconf):
        base = {"label": "synthetic-host", "logs": [], "exit_codes": {"check.sh": 0}, "artifact_digest": "n/a"}
        base.update(pconf)
        return ev.row_for("macos", base, self.LOGS, self.TESTS, [], {})

    def test_all_required_exits_zero_verifies(self):
        self.assertEqual(self.row()["status"], "verified")

    def test_a_required_nonzero_exit_prevents_verified(self):
        row = self.row(exit_codes={"check.sh": 101})
        self.assertNotEqual(row["status"], "verified")
        self.assertEqual(row["failed_commands"], ["check.sh"])
        row = self.row(exit_codes={"run-linux.sh": 0, "every test binary": 1})
        self.assertNotEqual(row["status"], "verified")

    def test_unrecorded_or_malformed_exits_prevent_verified(self):
        self.assertNotEqual(self.row(exit_codes={})["status"], "verified")
        self.assertNotEqual(self.row(exit_codes={"check.sh": "0"})["status"], "verified")
        self.assertNotEqual(self.row(exit_codes={"check.sh": None})["status"], "verified")

    def test_an_expected_failing_negative_probe_is_separate_and_allows_verified(self):
        probes = {"pre-fix.txt": {"expected_exit": 101, "observed_exit": 101}}
        row = self.row(negative_probes=probes)
        self.assertEqual(row["status"], "verified")
        self.assertEqual(row["exit_codes"], {"check.sh": 0})
        self.assertEqual(row["negative_probes"], probes)
        self.assertNotIn("pre-fix.txt", row["exit_codes"])

    def test_a_negative_probe_that_did_not_fail_as_expected_prevents_verified(self):
        for probe in (
            {"expected_exit": 101, "observed_exit": 0},
            {"expected_exit": 101, "observed_exit": 1},
            {"expected_exit": 0, "observed_exit": 0},
            {"observed_exit": 101},
        ):
            row = self.row(negative_probes={"probe": probe})
            self.assertNotEqual(row["status"], "verified", probe)
            self.assertEqual(row["failed_negative_probes"], ["probe"], probe)

    def test_a_negative_probe_listed_as_a_required_command_still_fails_it(self):
        # A failing probe placed in exit_codes is not reinterpreted as expected.
        row = self.row(exit_codes={"check.sh": 0, "pre-fix.txt": 101})
        self.assertNotEqual(row["status"], "verified")


class RowStatus137(unittest.TestCase):
    """ADR-0006 §13.7 item 6: an incomplete run is in_progress; blocked only for
    a platform or capability that is missing (AGENTS.md)."""

    TESTS = [("t", "a"), ("t", "b"), ("u", "c")]

    def row(self, logs, **pconf):
        base = {"label": "synthetic-host", "logs": [], "exit_codes": {"check.sh": 0}, "artifact_digest": "n/a"}
        base.update(pconf)
        return ev.row_for("macos", base, logs, self.TESTS, [], {})

    def test_an_expected_test_absent_from_a_current_build_run_is_in_progress(self):
        row = self.row({"t": {"a": "ok"}, "u": {"c": "ok"}})
        self.assertEqual(row["status"], "in_progress")
        self.assertEqual(row["incomplete_run"], ["t::b"])
        self.assertNotIn("blocked_on", row)

    def test_a_whole_target_absent_from_a_current_build_run_is_in_progress(self):
        row = self.row({"t": {"a": "ok", "b": "ok"}})
        self.assertEqual(row["status"], "in_progress")
        self.assertEqual(row["incomplete_run"], ["u::c"])
        self.assertEqual(row["missing_targets"], ["u"])
        self.assertNotIn("blocked_on", row)

    def test_the_end_to_end_flow_reports_an_incomplete_run_as_in_progress(self):
        logs = {"explicit_t": FULL["explicit_t"], "wild_t": {"w1": "ok", "w2": "ok"}}
        rc, summary, err = Scratch(self, logs).run()
        self.assertEqual(statuses(summary), ["in_progress"], err)
        self.assertEqual(statuses(summary, "G1"), ["in_progress"])
        claim = summary["exit_claims"]["claim"]["rows"][0]
        self.assertEqual(claim["status"], "in_progress")

    def test_a_missing_capability_for_the_absent_tests_is_blocked(self):
        reason = "a disposable second account (synthetic)"
        for key in ("t::b", "t"):
            row = self.row({"t": {"a": "ok"}, "u": {"c": "ok"}}, missing_capabilities={key: reason})
            self.assertEqual(row["status"], "blocked", key)
            self.assertEqual(row["blocked_on"], reason, key)
            self.assertNotIn("incomplete_run", row, key)

    def test_a_missing_capability_does_not_excuse_another_absent_test(self):
        row = self.row({"t": {"a": "ok"}}, missing_capabilities={"t::b": "synthetic capability"})
        self.assertEqual(row["status"], "in_progress")
        self.assertEqual(row["incomplete_run"], ["u::c"])

    def test_a_missing_capability_for_a_whole_target_is_blocked_not_a_missing_target(self):
        row = self.row({"t": {"a": "ok", "b": "ok"}}, missing_capabilities={"u": "synthetic capability"})
        self.assertEqual(row["status"], "blocked")
        self.assertNotIn("missing_targets", row)

    def test_a_missing_platform_is_blocked(self):
        reason = "no host of this platform is available (synthetic)"
        row = self.row({}, unavailable=reason, exit_codes={}, artifact_digest=None)
        self.assertEqual(row["status"], "blocked")
        self.assertEqual(row["blocked_on"], reason)
        self.assertEqual(row["passed"], 0)

    def test_a_platform_marked_missing_that_has_results_is_not_blocked(self):
        row = self.row({"t": {"a": "ok"}}, unavailable="synthetic")
        self.assertEqual(row["status"], "in_progress")

    def test_failures_still_outrank_a_missing_capability(self):
        row = self.row({"t": {"a": "FAILED"}, "u": {"c": "ok"}}, missing_capabilities={"t::b": "synthetic"})
        self.assertEqual(row["status"], "in_progress")

    def test_a_run_from_an_older_build_stays_in_progress(self):
        row = self.row({"t": {"a": "ok"}}, predates_build="older build (synthetic)",
                       missing_capabilities={"t::b": "synthetic"})
        self.assertEqual(row["status"], "in_progress")


if __name__ == "__main__":
    unittest.main(verbosity=2)
