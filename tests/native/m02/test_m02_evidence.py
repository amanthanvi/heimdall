#!/usr/bin/env python3
"""Self-test for m02-evidence.py, platform-tests.py and pty-answer.py (M02-U11).

Run from the repository root:  python3 -I tests/native/m02/test_m02_evidence.py

Everything is synthetic and lives in temporary directories, except the `RealFiles`
tests, which read the committed case index, runs.json, required inventory, the
M02 plan and the evidence README (read-only) and check that they agree with each
other and with the m02-plan section 3 and 4 tables.

What is pinned here:
  * the inventory: required tests come from the case index resolved against the
    sources, never from run logs; a pattern that resolves to nothing, an ambiguous
    exact name and a stale or drifting inventory are refused;
  * rows: verified only when every applicable required test ran and passed, every
    required command exited 0 and every negative probe exited as expected; a
    missing platform, a missing capability and an owner-input row are blocked with
    the exact input named; everything else incomplete is in_progress;
  * the lowest-row rule (tests/evidence/README.md), and records valid under
    tests/evidence/record.schema.json;
  * the run plan for the remote harnesses (build_host_paths, whole targets and
    single tests) and the platform-only compression of platform-tests.py;
  * pty-answer.py's typed-yes, timeout and signal exit codes.
"""

import importlib.util
import io
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ev = load("m02_evidence", "m02-evidence.py")
pt = load("platform_tests", "platform-tests.py")


def log_text(targets, style="cargo"):
    """A log: {target: {name: result}} as cargo prints it, or as a harness tests.txt."""
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


# --- a synthetic index, inventory and run ------------------------------------------------

INDEX = {
    "build_host": "macos",
    "platforms": {
        "macos": {"runs": "cargo"},
        "linux": {"runs": "cargo"},
        "windows": {"runs": "cargo"},
        "wsl-distro": {"runs": "scenario"},
    },
    "build_host_paths": {
        "t_files": {"neutral": True, "reason": "reads docs at the compile-time path"},
        "t_exact::e_gap": {"neutral": False, "reason": "reads schemas at the compile-time path"},
    },
    "groups": {
        "G1": {
            "title": "synthetic",
            "requirement_ids": ["R-UX-01"],
            "tests": {
                "t_exact": ["e1", "e_gap"],
                "t_wild": "*",
                "t_pre": ["pre_*", "*_suffix"],
                "t_files": ["f1"],
                "scn": ["s1", "s2"],
            },
            "blocked_rows": [
                {"platform": "synthetic owner row", "status": "blocked", "blocked_on": "B3: a disposable account"}
            ],
            "declared_platforms": ["macos", "linux", "windows", "wsl-distro"],
        },
        "G2": {
            "title": "synthetic, no owner row",
            "requirement_ids": [],
            "tests": {"t_exact": ["e1"]},
            "declared_platforms": ["macos", "linux", "windows"],
        },
    },
    "exit_claims": {
        "claim": {"groups": ["G1", "G2"], "note": "synthetic claim"},
        "own": {"tests": {"t_exact": ["e1"]}, "declared_platforms": ["macos"]},
    },
    "child_entries": {"t_wild::child": "re-executed child entry point"},
    "scenario_targets": {
        "scn": {"platforms": ["wsl-distro"], "steps": {"s1": "step one", "s2": "step two"}}
    },
}
LISTING = {
    "t_exact": ["e1", "e_gap", "e_other"],
    "t_wild": ["w1", "w2", "child", "m::w3"],
    "t_pre": ["pre_a", "pre_b", "x_suffix", "unrelated"],
    "t_files": ["f1", "f2"],
}
INVENTORY_TESTS = {
    "t_exact": ["e1", "e_gap"],
    "t_wild": ["m::w3", "w1", "w2"],
    "t_pre": ["pre_a", "pre_b", "x_suffix"],
    "t_files": ["f1"],
    "scn": ["s1", "s2"],
}


def make_inventory(**kw):
    return ev.build_inventory(INDEX, LISTING.get, "macos", kw.get("scans"), "digest-1")


def full_logs():
    return {
        "t_exact": {"e1": "ok", "e_gap": "ok"},
        "t_wild": {"w1": "ok", "w2": "ok", "m::w3": "ok"},
        "t_pre": {"pre_a": "ok", "pre_b": "ok", "x_suffix": "ok"},
        "t_files": {"f1": "ok"},
    }


def copy(o):
    return json.loads(json.dumps(o))


class Scratch:
    """A temporary index, inventory, run logs, config and sources; runs main()."""

    def __init__(self, testcase, logs=None, index=INDEX, inventory="build", platforms=None,
                 records=None, digest_ok=True, extra_cfg=None):
        self.tmp = tempfile.TemporaryDirectory(prefix="m02ev")
        testcase.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        self.dir = d
        (d / "src" / "tests").mkdir(parents=True)
        (d / "src" / "tests" / "a.rs").write_text("fn a() {}\n")
        digest = ev.sources_digest(d / "src")
        (d / "case-index.json").write_text(json.dumps(index))
        if inventory == "build":
            inv = ev.build_inventory(index, LISTING.get, "macos", None, digest if digest_ok else "other")
        else:
            inv = inventory
        if inv is not None:
            (d / "required-inventory.json").write_text(json.dumps(inv))
        logs = full_logs() if logs is None else logs
        base = {}
        for pname, sty in (("macos", "cargo"), ("linux", "harness"), ("windows", "harness")):
            (d / f"{pname}.log").write_text(log_text(logs, sty))
            (d / f"{pname}.commands").write_text("exit 0: the required command\n")
            (d / f"{pname}.facts").write_text("ssh-V=OpenSSH_synthetic (exit 0)\nos=synthetic\nsecret-thing=must not be kept\n")
            base[pname] = {
                "label": f"{pname}-synthetic",
                "logs": [f"{pname}.log"],
                "commands_logs": [f"{pname}.commands"],
                "facts": [f"{pname}.facts"],
                "artifact_digest": "n/a",
            }
        (d / "wsl.log").write_text(log_text({"scn": {"s1": "ok", "s2": "ok"}}, "harness"))
        (d / "wsl.commands").write_text("exit 0: the required command\n")
        (d / "wsl.facts").write_text("fact-free=1\n")
        base["wsl-distro"] = {
            "label": "wsl-synthetic",
            "logs": ["wsl.log"],
            "commands_logs": ["wsl.commands"],
            "facts": ["wsl.facts"],
            "artifact_digest": "n/a",
        }
        for pname, upd in (platforms or {}).items():
            base[pname].update(upd)
        self.record_paths = {sid: d / f"{i}.json" for i, sid in enumerate(["G1", "G2", "claim", "own"])}
        recs = records or {
            sid: {
                "case_id": f"case-{sid}",
                "path": str(self.record_paths[sid]),
                "requirement_ids": ["R-UX-01"],
                "summary": f"synthetic {sid}",
                "limitations": [],
            }
            for sid in ("G1", "G2", "claim", "own")
        }
        self.cfg = {
            "case_index": str(d / "case-index.json"),
            "required_inventory": str(d / "required-inventory.json"),
            "sources_root": str(d / "src"),
            "summary_out": str(d / "summary.json"),
            "artifacts_root": str(d),
            "build_commit": "0" * 40,
            "artifact_digest": "n/a",
            "started_at": "2026-11-04T00:00:00+00:00",
            "commands": ["synthetic"],
            "evidence_paths": ["synthetic"],
            "common_limitations": ["synthetic limitation"],
            "platforms": base,
            "records": recs,
        }
        self.cfg.update(extra_cfg or {})
        (d / "runs.json").write_text(json.dumps(self.cfg))

    def run(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                rc = ev.main(["--config", str(self.dir / "runs.json"), *args])
            except SystemExit as e:
                rc = e.code
        self.stdout = out.getvalue()
        summary_path = self.dir / "summary.json"
        summary = json.loads(summary_path.read_text()) if summary_path.exists() else None
        return rc, summary, err.getvalue()

    def records(self):
        return {sid: json.loads(p.read_text()) for sid, p in self.record_paths.items() if p.exists()}


def row_status(summary, sid, platform_prefix, kind="groups"):
    rows = [r for r in summary[kind][sid]["rows"] if r["platform"].startswith(platform_prefix)]
    assert len(rows) == 1, rows
    return rows[0]["status"]


# --- patterns ------------------------------------------------------------------------------


class Patterns(unittest.TestCase):
    CASES = [
        ("*", "any::thing", True),
        ("a1", "m::a1", True),
        ("a1", "a1", True),
        ("a1", "m::a10", False),
        ("a1", "m::xa1", False),
        ("pre_*", "pre_x", True),
        ("pre_*", "m::pre_x", True),
        ("pre_*", "m::x_pre_x", False),
        ("m::*", "m::x", True),
        ("m::*", "n::m::x", False),
        ("*_tail", "m::a_tail", True),
        ("*_tail", "m::a_tail2", False),
        ("*mid*", "m::a_mid_b", True),
        ("*mid*", "m::a_m_b", False),
        ("u9::a1_*", "u9::a1_x", True),
        ("u9::a1_*", "w::u9::a1_x", False),
    ]

    def test_matching_table(self):
        for item, name, want in self.CASES:
            self.assertEqual(ev.matches(item, name), want, (item, name))

    def test_pattern_detection(self):
        self.assertTrue(ev.is_pattern("*"))
        self.assertTrue(ev.is_pattern("a*"))
        self.assertTrue(ev.is_pattern("*a"))
        self.assertFalse(ev.is_pattern("a::b"))
        self.assertEqual(ev.spec_items("*"), ["*"])
        self.assertEqual(ev.spec_items(["a", "b*"]), ["a", "b*"])


# --- the run plan --------------------------------------------------------------------------


class RunPlan(unittest.TestCase):
    TARGETS = [("t_exact", "/x/t_exact"), ("t_files", "/x/t_files"), ("t_wild", "/x/t_wild")]

    def test_the_build_host_runs_everything_and_skips_nothing(self):
        run, skips, report = ev.skip_plan(INDEX, "macos", self.TARGETS)
        self.assertEqual([n for n, _ in run], ["t_exact", "t_files", "t_wild"])
        self.assertEqual(skips, [])
        self.assertEqual(report, [])

    def test_a_remote_platform_drops_whole_targets_and_skips_single_tests(self):
        run, skips, report = ev.skip_plan(INDEX, "linux", self.TARGETS)
        self.assertEqual([n for n, _ in run], ["t_exact", "t_wild"], "t_files is a build-host path")
        self.assertEqual(skips, [("t_exact", "e_gap")])
        text = "\n".join(report)
        self.assertIn("t_files: not run on linux (platform-neutral, run on the build host)", text)
        self.assertIn("t_exact::e_gap: skipped on linux (harness gap)", text)

    def test_a_scenario_or_unknown_platform_is_refused(self):
        with self.assertRaises(ev.PlanError):
            ev.skip_plan(INDEX, "wsl-distro", self.TARGETS)
        with self.assertRaises(ev.PlanError):
            ev.skip_plan(INDEX, "freebsd", self.TARGETS)

    def test_an_entry_for_a_target_that_was_not_built_is_refused(self):
        index = copy(INDEX)
        index["build_host_paths"]["ghost::x"] = {"neutral": True, "reason": "r"}
        with self.assertRaises(ev.PlanError):
            ev.skip_plan(index, "linux", self.TARGETS)

    def test_an_entry_needs_a_boolean_and_a_reason(self):
        for bad in ({"neutral": "yes", "reason": "r"}, {"neutral": True}, {"neutral": True, "reason": ""}, "x"):
            index = copy(INDEX)
            index["build_host_paths"]["t_files"] = bad
            with self.assertRaises(ev.PlanError, msg=str(bad)):
                ev.skip_plan(index, "linux", self.TARGETS)

    def test_the_command_writes_the_files_the_harness_reads(self):
        with tempfile.TemporaryDirectory(prefix="m02plan") as d:
            d = Path(d)
            (d / "index.json").write_text(json.dumps(INDEX))
            (d / "all.tsv").write_text("".join(f"{n}\t{e}\n" for n, e in self.TARGETS))
            args = ["--skip-plan", "windows", "--case-index", str(d / "index.json"), "--targets", str(d / "all.tsv"),
                    "--run-out", str(d / "run.tsv"), "--skips-out", str(d / "skips.tsv"), "--report-out", str(d / "skipped.txt")]
            (d / "skipped.txt").write_text("earlier line\n")
            self.assertEqual(ev.main(args), 0)
            self.assertEqual((d / "run.tsv").read_text(), "t_exact\t/x/t_exact\nt_wild\t/x/t_wild\n")
            self.assertEqual((d / "skips.tsv").read_text(), "t_exact\te_gap\n")
            text = (d / "skipped.txt").read_text()
            self.assertTrue(text.startswith("earlier line\n"), "the report is appended to")
            self.assertIn("t_files", text)
            err = io.StringIO()
            with redirect_stderr(err):
                self.assertEqual(ev.main(["--skip-plan", "wsl-distro", *args[2:]]), 2)
            self.assertIn("runs no cargo test binaries", err.getvalue())


# --- the inventory -------------------------------------------------------------------------


class Inventory(unittest.TestCase):
    def test_patterns_resolve_against_the_sources_and_child_entries_are_left_out(self):
        inv = make_inventory()
        self.assertEqual(inv["groups"]["G1"]["tests"], INVENTORY_TESTS)
        self.assertNotIn("child", inv["groups"]["G1"]["tests"]["t_wild"])
        self.assertEqual(inv["sources_sha256"], "digest-1")
        self.assertEqual(inv["exit_claims"]["own"]["tests"], {"t_exact": ["e1"]})

    def test_a_pattern_that_resolves_to_nothing_is_a_defect(self):
        index = copy(INDEX)
        index["groups"]["G2"]["tests"] = {"t_exact": ["nothing_*"]}
        with self.assertRaises(ev.InventoryError) as cm:
            ev.build_inventory(index, LISTING.get, "macos")
        self.assertIn("resolves to no test", str(cm.exception))

    def test_a_whole_target_with_zero_tests_is_a_defect(self):
        listing = copy(LISTING)
        listing["t_wild"] = ["child"]
        with self.assertRaises(ev.InventoryError):
            ev.build_inventory(INDEX, listing.get, "macos")
        del listing["t_wild"]
        with self.assertRaises(ev.InventoryError):
            ev.build_inventory(INDEX, listing.get, "macos")

    def test_an_explicit_name_the_sources_do_not_define_is_a_defect(self):
        listing = copy(LISTING)
        listing["t_exact"] = ["e1"]
        with self.assertRaises(ev.InventoryError):
            ev.build_inventory(INDEX, listing.get, "macos")

    def test_an_ambiguous_exact_name_is_a_defect(self):
        listing = copy(LISTING)
        listing["t_exact"] = ["e1", "a::e_gap", "b::e_gap"]
        with self.assertRaises(ev.InventoryError) as cm:
            ev.build_inventory(INDEX, listing.get, "macos")
        self.assertIn("ambiguous", str(cm.exception))

    def test_a_scenario_step_must_be_declared_and_never_a_pattern(self):
        for bad in (["s3"], ["s*"], ["*"]):
            index = copy(INDEX)
            index["groups"]["G2"]["tests"] = {"scn": bad}
            with self.assertRaises(ev.InventoryError, msg=str(bad)):
                ev.build_inventory(index, LISTING.get, "macos")

    def test_scans_add_platform_only_tests_and_the_platform_extras_a_pattern_covers(self):
        scans = {
            "windows": {
                "t_exact": {"present": 2, "absent": [], "extra": []},
                "t_wild": {"present": 3, "absent": ["w2"], "extra": ["win::w9", "unrelated_extra"]},
                "t_pre": {"present": 3, "absent": [], "extra": ["pre_win_only"]},
                "t_files": {"present": 1, "absent": [], "extra": []},
            }
        }
        index = copy(INDEX)
        index["groups"]["G1"]["tests"]["t_wild"] = ["w*", "win::*"]
        inv = ev.build_inventory(index, LISTING.get, "macos", scans, "d")
        self.assertEqual(inv["scanned_platforms"], ["windows"])
        self.assertEqual(inv["platform_extra"]["G1"]["windows"]["t_wild"], ["win::w9"])
        self.assertEqual(inv["platform_extra"]["G1"]["windows"]["t_pre"], ["pre_win_only"])
        self.assertEqual(inv["platform_only"]["t_wild::w2"], ["macos"])
        self.assertEqual(inv["platform_only"]["t_wild::win::w9"], ["windows"])
        self.assertEqual(inv["platform_only"]["t_pre::pre_win_only"], ["windows"])
        self.assertNotIn("t_wild::w1", inv["platform_only"], "present on every scanned platform")

    def test_check_accepts_the_generated_inventory_and_names_each_drift(self):
        inv = make_inventory()
        self.assertEqual(ev.check_inventory(INDEX, inv), [])
        inv2 = copy(inv)
        inv2["groups"]["G1"]["tests"]["t_exact"] = ["e1"]
        self.assertTrue(any("e_gap" in p for p in ev.check_inventory(INDEX, inv2)))
        inv2 = copy(inv)
        del inv2["groups"]["G1"]["tests"]["t_wild"]
        self.assertTrue(any("t_wild" in p and "missing" in p for p in ev.check_inventory(INDEX, inv2)))
        inv2 = copy(inv)
        inv2["groups"]["G1"]["tests"]["t_wild"] = []
        self.assertTrue(any("inventory for t_wild is empty" in p for p in ev.check_inventory(INDEX, inv2)))
        inv2 = copy(inv)
        inv2["groups"]["G1"]["tests"]["t_exact"].append("stray")
        self.assertTrue(any("stray" in p and "not covered" in p for p in ev.check_inventory(INDEX, inv2)))
        inv2 = copy(inv)
        inv2["groups"]["G1"]["tests"]["t_wild"].append("stray_wild")
        self.assertEqual(ev.check_inventory(INDEX, inv2), [], "a whole-target entry covers any name")
        inv2 = copy(inv)
        inv2["groups"]["G1"]["tests"]["scn"] = ["s1"]
        self.assertTrue(any("scenario step scn::s2" in p for p in ev.check_inventory(INDEX, inv2)))
        inv2 = copy(inv)
        inv2["groups"]["ghost"] = {"tests": {}}
        self.assertTrue(any("ghost" in p for p in ev.check_inventory(INDEX, inv2)))
        inv2 = copy(inv)
        del inv2["exit_claims"]["own"]
        self.assertTrue(any("own: no required inventory" in p for p in ev.check_inventory(INDEX, inv2)))

    def test_a_missing_inventory_writes_nothing(self):
        s = Scratch(self, inventory=None)
        rc, summary, err = s.run()
        self.assertEqual(rc, 2)
        self.assertIsNone(summary)
        self.assertIn("run --generate-inventory", err)

    def test_an_inventory_from_other_sources_is_refused_but_its_structure_checks(self):
        s = Scratch(self, digest_ok=False)
        rc, summary, err = s.run()
        self.assertEqual(rc, 1)
        self.assertIsNone(summary)
        self.assertIn("generated from other sources", err)
        self.assertEqual(s.run("--check-inventory")[0], 0)
        self.assertIn("generated from other sources", s.stdout)

    def test_an_inventory_that_drifts_from_the_index_is_refused(self):
        inv = make_inventory()
        inv["groups"]["G1"]["tests"]["t_wild"] = []
        rc, summary, err = Scratch(self, inventory=inv).run()
        self.assertEqual(rc, 1)
        self.assertIsNone(summary)
        self.assertIn("t_wild", err)


# --- rows ----------------------------------------------------------------------------------


class Rows(unittest.TestCase):
    """row_for(): the status of one platform's row."""

    TESTS = [("t", "a"), ("t", "b"), ("u", "c")]
    LOGS = {"t": {"a": "ok", "b": "ok"}, "u": {"c": "ok"}}

    def row(self, logs=None, tests=None, platform="linux", index=INDEX, obs=None, **pconf):
        base = {"label": "synthetic-host", "logs": [], "exit_codes": {"cmd": 0}, "artifact_digest": "n/a"}
        base.update(pconf)
        return ev.row_for(index, platform, base, self.LOGS if logs is None else logs,
                          self.TESTS if tests is None else tests, obs)

    def test_all_passed_and_all_commands_zero_is_verified(self):
        r = self.row()
        self.assertEqual(r["status"], "verified")
        self.assertEqual(r["passed"], 3)

    def test_a_failed_or_ignored_test_is_in_progress(self):
        self.assertEqual(self.row({"t": {"a": "FAILED", "b": "ok"}, "u": {"c": "ok"}})["status"], "in_progress")
        r = self.row({"t": {"a": "ok", "b": "ignored"}, "u": {"c": "ok"}})
        self.assertEqual(r["status"], "in_progress")
        self.assertEqual(r["ignored"], ["t::b"])

    def test_an_absent_test_is_an_incomplete_run_never_blocked(self):
        r = self.row({"t": {"a": "ok"}, "u": {"c": "ok"}})
        self.assertEqual(r["status"], "in_progress")
        self.assertEqual(r["incomplete_run"], ["t::b"])
        self.assertNotIn("blocked_on", r)
        r = self.row({"t": {"a": "ok", "b": "ok"}})
        self.assertEqual(r["missing_targets"], ["u"])
        self.assertEqual(r["status"], "in_progress")

    def test_nonzero_unrecorded_or_malformed_required_exits_prevent_verified(self):
        for codes in ({"cmd": 1}, {"cmd": 0, "other": 101}, {}, {"cmd": "0"}, {"cmd": None}, {"cmd": False}):
            r = self.row(exit_codes=codes)
            self.assertNotEqual(r["status"], "verified", codes)

    def test_negative_probes_are_separate_and_must_fail_as_expected(self):
        probes = {"pre-fix": {"expected_exit": 101, "observed_exit": 101}}
        r = self.row(negative_probes=probes)
        self.assertEqual(r["status"], "verified")
        self.assertEqual(r["exit_codes"], {"cmd": 0})
        for probe in ({"expected_exit": 101, "observed_exit": 0}, {"expected_exit": 0, "observed_exit": 0},
                      {"observed_exit": 101}, {"expected_exit": 101}):
            r = self.row(negative_probes={"p": probe})
            self.assertNotEqual(r["status"], "verified", probe)
            self.assertEqual(r["failed_negative_probes"], ["p"], probe)

    def test_build_host_path_tests_on_a_remote_platform(self):
        index = copy(INDEX)
        index["build_host_paths"] = {"t::a": {"neutral": True, "reason": "r"}, "u": {"neutral": False, "reason": "r"}}
        logs = {"t": {"b": "ok"}}
        r = self.row(logs, tests=[("t", "a"), ("t", "b")], index=index)
        self.assertEqual(r["status"], "verified")
        self.assertEqual(r["platform_neutral_run_elsewhere"], ["t::a"])
        r = self.row({"t": {"b": "ok"}}, tests=[("t", "b"), ("u", "c")], index=index)
        self.assertEqual(r["status"], "in_progress")
        self.assertEqual(r["harness_gap_not_run"], ["u::c"], "a non-neutral build-host path is a harness gap")
        # On the build host the same test is an ordinary absent test.
        r = self.row({"t": {"b": "ok"}}, tests=[("t", "a"), ("t", "b")], index=index, platform="macos")
        self.assertEqual(r["incomplete_run"], ["t::a"])

    def test_a_missing_platform_is_blocked_with_the_input_named(self):
        reason = "no host of this platform is available (synthetic)"
        r = self.row({}, unavailable=reason, exit_codes={}, artifact_digest=None)
        self.assertEqual(r["status"], "blocked")
        self.assertEqual(r["blocked_on"], reason)
        self.assertEqual(r["passed"], 0)
        # A platform marked unavailable that has results is not blocked.
        self.assertEqual(self.row(unavailable="synthetic")["status"], "in_progress")

    def test_a_missing_capability_blocks_only_what_it_names(self):
        reason = "a disposable second account (synthetic)"
        for key in ("t::b", "t"):
            r = self.row({"t": {"a": "ok"}, "u": {"c": "ok"}}, missing_capabilities={key: reason})
            self.assertEqual(r["status"], "blocked", key)
            self.assertEqual(r["blocked_on"], reason, key)
            self.assertNotIn("incomplete_run", r)
        r = self.row({"t": {"a": "ok"}}, missing_capabilities={"t::b": reason})
        self.assertEqual(r["status"], "in_progress", "u::c is still unexplained")
        r = self.row({"t": {"a": "FAILED", "b": "ok"}, "u": {"c": "ok"}}, missing_capabilities={"t::b": reason})
        self.assertEqual(r["status"], "in_progress", "failures outrank a missing capability")

    def test_an_older_build_stays_in_progress(self):
        r = self.row({"t": {"a": "ok"}, "u": {"c": "ok"}}, predates_build="older build (synthetic)",
                     missing_capabilities={"t::b": "synthetic"})
        self.assertEqual(r["status"], "in_progress")
        self.assertEqual(r["predates_build"], "older build (synthetic)")
        self.assertIn("not_run_since_build", r)

    def test_a_row_carries_the_observations_of_its_passed_tests_only(self):
        obs = {"t": {"a": ["observation test=a one", "observation test=a two"], "b": ["observation test=b"]},
               "u": {"c": ["observation test=c"], "zz": ["observation of a test no case requires"]}}
        r = self.row({"t": {"a": "ok", "b": "FAILED"}, "u": {"c": "ok"}}, obs=obs)
        self.assertEqual(r["observations"], {"t::a": ["observation test=a one", "observation test=a two"], "u::c": ["observation test=c"]})
        self.assertNotIn("observations_truncated", r)
        self.assertEqual(r["status"], "in_progress", "a failed test still decides the status")
        self.assertNotIn("observations", self.row({"t": {"a": "ok", "b": "ok"}, "u": {"c": "ok"}}, obs={}))

    def test_observations_per_row_are_bounded_and_say_so(self):
        n = ev.OBSERVATION_LINES_PER_ROW // ev.OBSERVATION_LINES_PER_TEST + 2
        tests = [("t", f"a{i}") for i in range(n)]
        obs = {"t": {f"a{i}": [f"observation i={i} j={j}" for j in range(ev.OBSERVATION_LINES_PER_TEST)] for i in range(n)}}
        logs = {"t": {name: "ok" for _, name in tests}}
        r = self.row(logs, tests=tests, obs=obs)
        self.assertEqual(sum(len(v) for v in r["observations"].values()), ev.OBSERVATION_LINES_PER_ROW)
        self.assertTrue(r["observations_truncated"])

    def test_a_row_with_no_applicable_test_is_none(self):
        self.assertIsNone(self.row({}, tests=[]))


# --- applicability -------------------------------------------------------------------------


class Applicability(unittest.TestCase):
    INV = {"platform_only": {"t": ["macos"], "t::a::": ["macos", "linux"], "t::a::x*": ["linux"], "t::a::b": ["windows"]}}

    def look(self, name):
        return ev.platform_only_lookup({}, self.INV, "t", name)

    def test_the_most_specific_entry_wins(self):
        self.assertEqual(self.look("a::b"), ["windows"], "exact name")
        self.assertEqual(self.look("a::xy"), ["linux"], "longest prefix pattern")
        self.assertEqual(self.look("a::c"), ["macos", "linux"], "module prefix")
        self.assertEqual(self.look("z"), ["macos"], "target-wide entry")
        self.assertIsNone(ev.platform_only_lookup({}, self.INV, "other", "z"))

    def test_the_case_index_entries_override_the_inventory(self):
        index = {"platform_only": {"t::a::c": ["windows"]}}
        self.assertEqual(ev.platform_only_lookup(index, self.INV, "t", "a::c"), ["windows"])

    def test_applicable_follows_the_inventory_platform_only_entries(self):
        inv = make_inventory()
        inv["platform_only"] = {"t_exact::e1": ["macos", "linux"]}
        self.assertTrue(ev.applicable(INDEX, inv, "t_exact", "e1", "linux"))
        self.assertFalse(ev.applicable(INDEX, inv, "t_exact", "e1", "windows"))
        self.assertTrue(ev.applicable(INDEX, inv, "t_exact", "e_gap", "windows"), "no entry: applies everywhere")
        self.assertEqual([t for t in ev.required(INDEX, inv, "groups", "G2", "windows")], [],
                         "the one test G2 requires is Unix-only here, so no row for Windows")

    def test_scenario_targets_apply_only_on_their_platforms(self):
        inv = make_inventory()
        self.assertTrue(ev.applicable(INDEX, inv, "scn", "s1", "wsl-distro"))
        self.assertFalse(ev.applicable(INDEX, inv, "scn", "s1", "linux"))
        self.assertFalse(ev.applicable(INDEX, inv, "t_exact", "e1", "wsl-distro"), "no cargo tests there")
        self.assertFalse(ev.applicable(INDEX, inv, "t_wild", "child", "macos"), "child entry points never apply")


# --- parsing -------------------------------------------------------------------------------


class Parsing(unittest.TestCase):
    def parse(self, text):
        with tempfile.TemporaryDirectory(prefix="m02parse") as d:
            p = Path(d) / "log"
            p.write_text(text)
            return ev.parse_log(p)

    def test_cargo_output_names_integration_targets_and_unit_targets(self):
        got = self.parse(
            "     Running unittests src/lib.rs (target/debug/deps/heimdall_x-0123abcd)\n"
            "running 2 tests\ntest a::b ... ok\ntest c ... FAILED\n"
            "     Running tests/model/thing.rs (target/debug/deps/model_thing-0123abcd)\n"
            "test d ... ignored\n"
            "     Running ../../tests/integration/y.rs (target/debug/deps/integration_y-ffff)\n"
            "test e ... ok\n"
            "   Doc-tests heimdall_x\n"
            "test not::counted ... ok\n"
        )
        self.assertEqual(got["heimdall_x-unit"], {"a::b": "ok", "c": "FAILED"})
        self.assertEqual(got["model_thing"], {"d": "ignored"})
        self.assertEqual(got["integration_y"], {"e": "ok"})
        self.assertNotIn("not::counted", json.dumps(got))

    def test_windows_style_paths_and_ansi_escapes(self):
        got = self.parse(
            "\x1b[32m     Running\x1b[0m tests\\x\\z.rs (target\\debug\\deps\\e2e_z-0123abcd.exe)\r\n"
            "test w ... ok\r\n"
        )
        self.assertEqual(got, {"e2e_z": {"w": "ok"}})

    def test_harness_output_uses_target_headers_and_exit_lines(self):
        got = self.parse("### t_a\ntest x ... ok\n### t_a exit=0\n### windows_launch\ntest ctrlc.event ... ok\ntest resize ... FAILED\n")
        self.assertEqual(got["t_a"], {"x": "ok"})
        self.assertEqual(got["windows_launch"], {"ctrlc.event": "ok", "resize": "FAILED"})

    def test_a_test_line_before_any_target_is_ignored(self):
        self.assertEqual(self.parse("test lost ... ok\n"), {})

    def observations(self, text):
        with tempfile.TemporaryDirectory(prefix="m02obs") as d:
            p = Path(d) / "log"
            p.write_text(text)
            return ev.parse_observations(p)

    def test_observation_lines_belong_to_the_test_whose_output_header_precedes_them(self):
        got = self.observations(
            "     Running ../../tests/integration/projection_replace.rs (target/debug/deps/integration_projection_replace-0123abcd)\n"
            "test a::exchange ... ok\ntest b ... ok\n\nsuccesses:\n\n"
            "---- a::exchange stdout ----\nobservation: exchange os=macos supported=true\n\n"
            "---- b stdout ----\nnoise\n  observation test=b client=ssh subject=x\nobservation test=b client=ssh subject=x\n\n"
            "successes:\n    a::exchange\n    b\n\ntest result: ok. 2 passed; 0 failed\n"
            "observation after the section belongs to no test\n"
        )
        t = got["integration_projection_replace"]
        self.assertEqual(t["a::exchange"], ["observation: exchange os=macos supported=true"])
        self.assertEqual(t["b"], ["observation test=b client=ssh subject=x"], "stripped and deduplicated")
        self.assertEqual(t[""], ["observation after the section belongs to no test"])

    def test_observation_lines_in_harness_logs_failures_and_other_targets(self):
        got = self.observations(
            "### t_a\ntest x ... FAILED\n\nfailures:\n\n---- x stdout ----\nobservation test=x why=failed\n"
            "failures:\n    x\n### t_a exit=101\n### t_b\n---- y stdout ----\nobservation test=y\n"
            "   Doc-tests foo\nobservation never kept\n"
        )
        self.assertEqual(got["t_a"], {"x": ["observation test=x why=failed"]})
        self.assertEqual(got["t_b"], {"y": ["observation test=y"]})
        self.assertNotIn("never kept", json.dumps(got))

    def test_a_word_that_merely_starts_with_observation_is_not_an_observation(self):
        self.assertEqual(self.observations("### t\n---- a stdout ----\nobservations are plural\nobservation_x\n"), {})

    def test_observation_lines_per_test_are_bounded(self):
        text = "### t\n---- a stdout ----\n" + "".join(f"observation n={i}\n" for i in range(ev.OBSERVATION_LINES_PER_TEST + 25))
        self.assertEqual(len(self.observations(text)["t"]["a"]), ev.OBSERVATION_LINES_PER_TEST)

    def test_commands_and_facts(self):
        with tempfile.TemporaryDirectory(prefix="m02parse") as d:
            c, f = Path(d) / "c", Path(d) / "f"
            c.write_text("exit 0: a command\nexit 101: another one\nnot a record\nexit -1: negative\n")
            f.write_text("ssh-V=OpenSSH_x (exit 0)\nos=a=b\nbad line\nssh-V=second wins nothing\n")
            self.assertEqual(ev.parse_commands(c), {"a command": 0, "another one": 101, "negative": -1})
            self.assertEqual(ev.parse_facts(f), {"ssh-V": "OpenSSH_x (exit 0)", "os": "a=b"})


# --- the lowest-row rule -------------------------------------------------------------------


class LowestRow(unittest.TestCase):
    def test_the_order_is_the_one_the_evidence_readme_states(self):
        text = (ROOT / "tests" / "evidence" / "README.md").read_text(encoding="utf-8")
        m = re.search(r"The order, lowest first, is((?:\s*`\w+`,?(?:\s+and)?)+)", text)
        self.assertIsNotNone(m, "the README states the order")
        self.assertEqual(re.findall(r"`(\w+)`", m.group(1)), ev.ORDER)
        self.assertEqual(ev.NOT_COUNTED, "deferred_with_decision")

    def test_lowest_picks_the_lowest_and_ignores_deferred_rows(self):
        self.assertEqual(ev.lowest(["verified", "blocked", "in_progress"]), "blocked")
        self.assertEqual(ev.lowest(["verified", "in_progress", "implemented_unverified"]), "in_progress")
        self.assertEqual(ev.lowest(["not_started", "in_progress"]), "not_started")
        self.assertEqual(ev.lowest(["verified", "deferred_with_decision"]), "verified")
        self.assertEqual(ev.lowest(["deferred_with_decision"]), "deferred_with_decision")
        for pair in ((a, b) for a in ev.ORDER for b in ev.ORDER):
            self.assertEqual(ev.lowest(list(pair)), min(pair, key=ev.ORDER.index))


# --- evaluation and records, end to end ------------------------------------------------------


class Records(unittest.TestCase):
    def test_a_complete_run_with_one_owner_row_is_blocked_with_the_input_named(self):
        s = Scratch(self)
        rc, summary, err = s.run("--write")
        self.assertEqual(rc, 0, err)
        # Every platform row verified; the owner-input row is blocked, so the group is.
        for p in ("macos", "linux", "windows"):
            self.assertEqual(row_status(summary, "G1", p), "verified", p)
        self.assertEqual(row_status(summary, "G1", "wsl"), "verified")
        self.assertEqual(row_status(summary, "G1", "synthetic owner row"), "blocked")
        self.assertEqual(summary["groups"]["G1"]["status"], "blocked")
        self.assertEqual(summary["groups"]["G2"]["status"], "verified")
        self.assertEqual(summary["exit_claims"]["claim"]["status"], "blocked", "a claim takes the lowest row of its groups")
        self.assertEqual(summary["exit_claims"]["own"]["status"], "verified")
        recs = s.records()
        self.assertEqual(recs["G1"]["status"], "blocked")
        self.assertEqual(recs["G1"]["blocked_on"], "B3: a disposable account")
        self.assertEqual(recs["claim"]["status"], "blocked")
        self.assertIsNone(recs["G2"]["blocked_on"])
        self.assertEqual(recs["G2"]["status"], "verified")

    def test_generated_records_validate_against_the_schema(self):
        s = Scratch(self)
        rc, _, err = s.run("--write")
        self.assertEqual(rc, 0, err)
        recs = s.records()
        self.assertEqual(sorted(recs), ["G1", "G2", "claim", "own"])
        for sid, rec in recs.items():
            self.assertEqual(ev.validate_record(rec), [], sid)
            self.assertEqual(rec["build_commit"], "0" * 40)
            self.assertIn("synthetic limitation", rec["limitations"])
            self.assertIsInstance(rec["observed_result"], dict)
            self.assertIn("rows", rec["observed_result"])
            self.assertIn("row_statuses", rec["observed_result"])
        # A record that breaks the schema is rejected before anything is written.
        self.assertNotEqual(ev.validate_record({"status": "blocked"}), [])
        bad = copy(recs["G1"])
        bad["status"] = "failed"
        self.assertNotEqual(ev.validate_record(bad), [])
        bad = copy(recs["G1"])
        self.assertEqual(bad["status"], "blocked")
        del bad["blocked_on"]
        self.assertNotEqual(ev.validate_record(bad), [], "a blocked record needs blocked_on")

    def test_observation_lines_in_a_run_log_reach_the_platform_row_and_the_record(self):
        s = Scratch(self)
        text = (s.dir / "linux.log").read_text()
        text += "### t_exact\n---- e1 stdout ----\nobservation test=e1 os=linux supported=true\n"
        (s.dir / "linux.log").write_text(text)
        rc, summary, err = s.run("--write")
        self.assertEqual(rc, 0, err)
        row = [r for r in summary["groups"]["G2"]["rows"] if r["platform"].startswith("linux")][0]
        self.assertEqual(row["observations"], {"t_exact::e1": ["observation test=e1 os=linux supported=true"]})
        rec = s.records()["G2"]
        self.assertEqual(ev.validate_record(rec), [])
        self.assertIn("observation test=e1 os=linux supported=true", json.dumps(rec["observed_result"]))
        mac = [r for r in summary["groups"]["G2"]["rows"] if r["platform"].startswith("macos")][0]
        self.assertNotIn("observations", mac, "another platform's row does not borrow it")

    def test_environment_keeps_only_the_named_fact_keys(self):
        s = Scratch(self)
        s.run("--write")
        env = s.records()["G2"]["environment"]["host_facts"]
        self.assertEqual(env["linux"], {"ssh-V": "OpenSSH_synthetic (exit 0)", "os": "synthetic"})
        self.assertNotIn("secret-thing", json.dumps(env))
        self.assertTrue(any("ssh-V" in v for v in s.records()["G2"]["provider_versions"]))

    def test_a_failing_test_keeps_the_row_in_progress_and_the_exit_code_nonzero_only_for_inventory_issues(self):
        logs = full_logs()
        logs["t_wild"]["w1"] = "FAILED"
        s = Scratch(self, logs=logs)
        rc, summary, err = s.run()
        self.assertEqual(row_status(summary, "G2", "macos"), "verified", "G2 does not use t_wild")
        self.assertEqual(row_status(summary, "G1", "macos"), "in_progress")
        self.assertEqual(rc, 0, "a failing test is a row status, not a generator error")

    def test_dropping_a_whole_wildcard_target_or_one_test_cannot_verify(self):
        for drop in ("target", "one"):
            logs = full_logs()
            if drop == "target":
                del logs["t_wild"]
            else:
                del logs["t_wild"]["w2"]
            s = Scratch(self, logs=logs)
            rc, summary, err = s.run()
            self.assertNotEqual(rc, 0, drop)
            self.assertIn("t_wild", err)
            self.assertNotEqual(row_status(summary, "G1", "linux"), "verified", drop)
            self.assertNotEqual(summary["exit_claims"]["claim"]["status"], "verified", drop)

    def test_a_new_test_outside_the_inventory_needs_regeneration(self):
        logs = full_logs()
        logs["t_wild"]["w4"] = "ok"
        rc, _, err = Scratch(self, logs=logs).run()
        self.assertNotEqual(rc, 0)
        self.assertIn("w4", err)
        self.assertIn("regenerate", err)

    def test_a_declared_platform_without_an_applicable_test_is_a_gap_never_a_pass(self):
        index = copy(INDEX)
        index["groups"]["G2"]["declared_platforms"] = ["macos", "linux", "windows", "wsl-distro"]
        s = Scratch(self, index=index)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        gap = [r for r in summary["groups"]["G2"]["rows"] if r["platform"].startswith("wsl")][0]
        self.assertEqual(gap["status"], "in_progress")
        self.assertIn("no_applicable_test", gap)
        self.assertEqual(summary["groups"]["G2"]["status"], "in_progress")

    def test_a_declared_platform_with_no_run_configured_is_not_started(self):
        index = copy(INDEX)
        index["groups"]["G2"]["declared_platforms"] = ["macos", "linux", "windows", "freebsd"]
        rc, summary, err = Scratch(self, index=index).run()
        self.assertEqual(rc, 0, err)
        row = [r for r in summary["groups"]["G2"]["rows"] if r["platform"] == "freebsd"][0]
        self.assertEqual(row["status"], "not_started")
        self.assertEqual(summary["groups"]["G2"]["status"], "not_started")

    def test_an_unavailable_platform_is_blocked_with_its_input_and_needs_no_logs(self):
        s = Scratch(self, platforms={"windows": {"unavailable": "a Windows 11 x64 host (synthetic)"}})
        for name in ("windows.log", "windows.commands", "windows.facts"):
            (s.dir / name).unlink()
        rc, summary, err = s.run("--write")
        self.assertEqual(rc, 0, err)
        row = [r for r in summary["groups"]["G2"]["rows"] if r["platform"].startswith("windows")][0]
        self.assertEqual(row["status"], "blocked")
        self.assertEqual(row["blocked_on"], "a Windows 11 x64 host (synthetic)")
        rec = s.records()["G2"]
        self.assertEqual(rec["status"], "blocked")
        self.assertEqual(rec["blocked_on"], "a Windows 11 x64 host (synthetic)")
        self.assertEqual(ev.validate_record(rec), [])

    def test_tests_of_an_unavailable_platform_are_never_looked_for_in_the_logs(self):
        # ADR-0007 §12.32 item 10: a Windows-only test, with Windows marked unavailable
        # (nothing ran there), is not "not found in any log"; its row is blocked instead.
        index = copy(INDEX)
        index["groups"]["G2"]["tests"] = {"t_exact": ["e1", "e_other"]}
        index["platform_only"] = {"t_exact::e_other": ["windows"]}
        s = Scratch(self, index=index, platforms={"windows": {"unavailable": "a Windows host (synthetic)"}})
        for name in ("windows.log", "windows.commands", "windows.facts"):
            (s.dir / name).unlink()
        rc, summary, err = s.run()
        self.assertNotIn("not found in any log", err)
        self.assertEqual(rc, 0, err)
        self.assertEqual(row_status(summary, "G2", "windows"), "blocked")
        # The same test with Windows available but absent from its log is still reported.
        s = Scratch(self, index=index)
        rc, summary, err = s.run()
        self.assertIn("G2: t_exact::e_other not found in any log", err)
        self.assertEqual(rc, 1)

    def test_a_missing_capability_blocks_the_row_and_the_record_names_it(self):
        logs = full_logs()
        del logs["t_pre"]
        s = Scratch(self, logs=logs, platforms={"linux": {"missing_capabilities": {"t_pre": "a capability (synthetic)"}}})
        rc, summary, err = s.run("--write")
        self.assertEqual(row_status(summary, "G1", "linux"), "blocked")
        self.assertIn("a capability (synthetic)", s.records()["G1"]["blocked_on"])
        self.assertEqual(row_status(summary, "G1", "windows"), "in_progress", "the capability is named for linux only")

    def test_a_configured_log_that_does_not_exist_stops_before_anything_is_written(self):
        s = Scratch(self)
        (s.dir / "linux.log").unlink()
        rc, summary, err = s.run("--write")
        self.assertEqual(rc, 2)
        self.assertIsNone(summary)
        self.assertIn("linux", err)
        self.assertIn("not executed or not saved", err)
        self.assertEqual(s.records(), {})

    def test_a_required_command_with_a_nonzero_exit_keeps_the_platform_in_progress(self):
        s = Scratch(self)
        (s.dir / "windows.commands").write_text("exit 0: a\nexit 3: the failing step\n")
        rc, summary, _ = s.run()
        self.assertEqual(row_status(summary, "G2", "windows"), "in_progress")
        row = [r for r in summary["groups"]["G2"]["rows"] if r["platform"].startswith("windows")][0]
        self.assertEqual(row["failed_commands"], ["the failing step"])

    def test_an_owner_row_without_a_named_input_is_refused(self):
        index = copy(INDEX)
        index["groups"]["G1"]["blocked_rows"] = [{"platform": "x", "status": "blocked"}]
        s = Scratch(self, index=index)
        rc, summary, err = s.run("--write")
        self.assertEqual(rc, 2)
        self.assertIn("blocked without a named input", err)
        self.assertEqual(s.records(), {})

    def test_an_extra_row_cannot_claim_verified_without_a_log(self):
        s = Scratch(self, extra_cfg={"extra_rows": {"G2": [{"platform": "claimed", "status": "verified"}]}})
        rc, summary, err = s.run()
        self.assertEqual(rc, 1)
        self.assertIn("claims verified without a log", err)
        row = [r for r in summary["groups"]["G2"]["rows"] if r["platform"] == "claimed"][0]
        self.assertEqual(row["status"], "in_progress")

    def test_the_command_line_with_a_missing_config_is_a_usage_error(self):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                ev.main([])


# --- platform-tests.py ---------------------------------------------------------------------


# --- the Windows local-mode bundle (ADR-0007 §12.32 item 17) ------------------------------

wb = load("import_windows_bundle", "import-windows-bundle.py")


def make_bundle(files=None, commit="1" * 40, label="windows-synthetic", tamper=None):
    """A bundle as run-windows-local.ps1 writes it: JSON, gzip, base64 between the markers."""
    import base64
    import gzip
    import hashlib
    base = {
        "tests.txt": "### model_setup\nrunning 1 test\ntest a ... ok\n### model_setup exit=0\n",
        "commands.txt": "exit 0: every test binary natively\n",
        "host.txt": "os=Microsoft Windows [Version 10.0.26100.1000]\nssh-V-inbox=OpenSSH_for_Windows_10.3p1 (exit 0)\n",
        "build.txt": "",
        "skipped.txt": "",
        "canary-scan.txt": "canary-prefix occurrences in saved output: 0\n",
    }
    base.update(files or {})
    doc = {"format": wb.FORMAT, "commit": commit, "label": label,
           "files": base, "sha256": {k: hashlib.sha256(v.encode()).hexdigest() for k, v in base.items()}}
    if tamper:
        tamper(doc)
    packed = gzip.compress(json.dumps(doc).encode())
    b64 = base64.b64encode(packed).decode()
    lines = [wb.BEGIN, "sha256-gzip: " + hashlib.sha256(packed).hexdigest()]
    lines += [b64[i:i + 76] for i in range(0, len(b64), 76)]
    lines.append(wb.END)
    return "agent report text before\n" + "\n".join(lines) + "\nand after\n"


class WindowsBundle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="m02wb")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "artifacts"

    def test_a_valid_bundle_is_imported_where_the_generator_reads_it(self):
        dest, digest, n = wb.import_bundle(make_bundle(), "exit-x", self.root, commit="1" * 40)
        self.assertEqual(dest, self.root / "exit-x" / "windows")
        self.assertEqual(sorted(p.name for p in dest.iterdir()), sorted(wb.FILES))
        self.assertEqual(ev.parse_log(dest / "tests.txt"), {"model_setup": {"a": "ok"}})
        self.assertEqual(ev.parse_commands(dest / "commands.txt"), {"every test binary natively": 0})
        self.assertEqual(len(digest), 64)
        self.assertEqual(n, 1)
        self.assertFalse((self.root / "exit-x" / ".windows-import").exists())

    def test_the_config_is_pointed_at_the_files_and_loses_its_unavailable_mark(self):
        cfg_path = Path(self.tmp.name) / "runs.json"
        cfg = {"artifacts_root": str(self.root / "exit-x"),
               "platforms": {"windows": {"label": "old", "unavailable": "the PC was unreachable"}}}
        cfg_path.write_text(json.dumps(cfg))
        _, digest, _ = wb.import_bundle(make_bundle(), "exit-x", self.root, config=cfg_path)
        win = json.loads(cfg_path.read_text())["platforms"]["windows"]
        self.assertNotIn("unavailable", win)
        self.assertEqual(win["logs"], ["windows/tests.txt"])
        self.assertEqual(win["commands_logs"], ["windows/commands.txt"])
        self.assertEqual(win["facts"], ["windows/host.txt"])
        self.assertEqual(win["label"], "windows-synthetic")
        self.assertEqual(win["artifact_digest"], digest)
        # load_platforms reads exactly those files.
        plats = ev.load_platforms(json.loads(cfg_path.read_text()))
        self.assertIn("model_setup", plats["windows"][1])

    def test_a_refused_bundle_writes_nothing(self):
        def drop(name):
            return lambda d: d["files"].pop(name) and d["sha256"].pop(name)

        def rename(d):
            d["files"]["../escape.txt"] = d["files"].pop("build.txt")
            d["sha256"]["../escape.txt"] = d["sha256"].pop("build.txt")

        cases = {
            "no markers": "nothing here",
            "payload sha": make_bundle().replace("sha256-gzip: ", "sha256-gzip: 00"),
            "file sha": make_bundle(tamper=lambda d: d["sha256"].update({"tests.txt": "0" * 64})),
            "a missing file": make_bundle(tamper=drop("build.txt")),
            "a path": make_bundle(tamper=rename),
            "another format": make_bundle(tamper=lambda d: d.update({"format": "x/1"})),
            "a short commit": make_bundle(commit="abc"),
            "another commit": make_bundle(commit="2" * 40),
            "a canary": make_bundle({"tests.txt": "### t\ntest a ... ok\nHEIMDALL_CANARY_x\n### t exit=0\n"}),
            "a SID": make_bundle({"host.txt": "user=S-1-5-21-1-2-3-1001\n"}),
            "an Entra SID": make_bundle({"host.txt": "user=S-1-12-1-1-2-3-4\n"}),
            "an address": make_bundle({"build.txt": "peer 203.0.113.9\n"}),
            "no results": make_bundle({"tests.txt": "nothing\n"}),
            # ADR-0007 §12.35 item 3 (N03): metadata and the new content rules.
            "a canary in the label": make_bundle(label="win " + "HEIMDALL_" + "CANARY_" + "x"),
            "a home path in the label": make_bundle(label="run of C:\\Users\\someone"),
            "a control character in the label": make_bundle(label="a\x1bb"),
            "a long label": make_bundle(label="x" * 201),
            "private-key armor": make_bundle({"build.txt": "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n"}),
            "a Unix home path": make_bundle({"build.txt": "at /home/someone/src\n"}),
            "a Unix home after a placeholder": make_bundle({"build.txt": "at <scratch>/home/someone/src\n"}),
            "a Unix home whose name has a dot inside": make_bundle({"build.txt": "at /home/some.one/src\n"}),
            "a Windows home path": make_bundle({"build.txt": "at C:\\Users\\someone\\src\n"}),
            "a WSL view of a Windows home": make_bundle({"build.txt": "at /mnt/c/Users/someone/x\n"}),
            "a macOS home path": make_bundle({"build.txt": "at /Users/someone/x\n"}),
            # ADR-0007 §12.38 item 3 (L03): a personal name that merely starts with a system one.
            "a Windows profile named like Public": make_bundle({"build.txt": "at C:\\Users\\Public-Alice\\src\n"}),
            "a Windows profile named like Default": make_bundle({"build.txt": "at C:/Users/Default.Bob/src\n"}),
            "a WSL view of such a profile": make_bundle({"build.txt": "at /mnt/c/Users/Public.Alice/x\n"}),
            "a macOS home named like Shared": make_bundle({"build.txt": "at /Users/Shared-Alice/x\n"}),
            "a label naming such a profile": make_bundle(label="from C:\\Users\\Default-Bob"),
            # The K01 review: a space inside a personal name, and a longer name than an exempt one.
            "a Windows profile with a space": make_bundle({"build.txt": "at C:/Users/Public Alice/src\n"}),
            "a profile extending Default User": make_bundle({"build.txt": "at C:/Users/Default User.Alice/src\n"}),
            "a WSL view with a space": make_bundle({"build.txt": "at /mnt/c/Users/Public Alice/src\n"}),
            "a macOS home with a space": make_bundle({"build.txt": "at /Users/Shared Alice/src\n"}),
            # A macOS home after any colon other than a lone drive letter's.
            "a macOS home in a PATH list": make_bundle({"build.txt": "PATH=/usr/bin:/Users/someone/bin\n"}),
            "a macOS home in a file URL": make_bundle({"build.txt": "see file:/Users/someone/log\n"}),
            "a drive letter before a personal profile": make_bundle({"build.txt": "x:/Users/someone/y\n"}),
            "no commands": make_bundle({"commands.txt": "\n"}),
        }
        for why, text in cases.items():
            with self.subTest(why):
                with self.assertRaises(wb.Refused):
                    wb.import_bundle(text, "exit-x", self.root, commit="1" * 40)
                self.assertFalse((self.root / "exit-x" / "windows").exists(), why)
                self.assertFalse((self.root / "exit-x" / ".windows-import").exists(), why)

    def test_redacted_and_system_paths_are_accepted(self):
        # The placeholders the runner writes, and Windows' own profile folders, are not leaks.
        files = {"build.txt": "C:\\Users\\<winuser>\\src and <winhome>\\x and C:\\Users\\Public\\y and "
                              "/home/<wsluser>/z and /hm/home/fixture and /mnt/c/Users/<winuser>/w\n"}
        dest, _, _ = wb.import_bundle(make_bundle(files), "exit-ok", self.root)
        self.assertTrue((dest / "build.txt").exists())

    def test_a_fixture_home_directory_dotfile_is_not_a_home(self):
        # The Windows exit run at 1e69263d: a Git observation line names the fixture's own
        # `home` directory under the redacted scratch root. A user name never starts with ".".
        files = {"build.txt": 'git_var_global="<scratch>/home/.config/git/config,<scratch>/home/.gitconfig"\n'}
        dest, _, _ = wb.import_bundle(make_bundle(files), "exit-dot", self.root)
        self.assertTrue((dest / "build.txt").exists())

    def test_exact_system_profiles_stay_accepted(self):
        files = {"build.txt": "C:\\Users\\Public\\a and C:/Users/Default/b and /mnt/c/Users/Public/c "
                              "and /Users/Shared/d and C:\\Users\\All Users\\e and C:\\Users\\Default User\\f\n"}
        dest, _, _ = wb.import_bundle(make_bundle(files), "exit-sys", self.root)
        self.assertTrue((dest / "build.txt").exists())

    def test_the_cli_reads_at_most_the_bound_plus_one(self):
        # ADR-0007 §12.38 item 4 (L04): the command line never reads a report whole before the
        # bound is checked; it asks the open file for at most MAX_REPORT + 1 bytes.
        import builtins
        import unittest.mock
        big = Path(self.tmp.name) / "big.txt"
        big.write_bytes(b"x" * 4096)
        asked = []
        real_open = builtins.open

        def spy_open(path, mode="r", *a, **k):
            f = real_open(path, mode, *a, **k)
            if str(path) == str(big):
                real_read = f.read

                def read(n=-1):
                    asked.append(n)
                    return real_read(n)
                f.read = read
            return f
        with unittest.mock.patch.object(wb, "MAX_REPORT", 1024), \
                unittest.mock.patch("builtins.open", spy_open):
            rc = wb.main(["--bundle", str(big), "--label", "exit-big", "--artifacts-root", str(self.root)])
        self.assertEqual(rc, 1)
        self.assertEqual(asked, [1025], "exactly one bounded read of MAX_REPORT + 1 bytes")
        self.assertFalse((self.root / "exit-big").exists())

    def test_decompression_is_bounded_and_stops_early(self):
        # ADR-0007 §12.35 item 3 (N04): a small payload that inflates past the bound is refused
        # without ever producing more than MAX_PAYLOAD + 1 bytes.
        import base64
        import gzip
        import hashlib
        import unittest.mock
        packed = gzip.compress(b"\0" * (wb.MAX_PAYLOAD + 4096))
        b64 = base64.b64encode(packed).decode()
        text = "\n".join([wb.BEGIN, "sha256-gzip: " + hashlib.sha256(packed).hexdigest(), b64, wb.END])
        seen = []
        real = wb.zlib.decompressobj

        def spy(*a, **k):
            d = real(*a, **k)

            class Wrap:
                def decompress(self, data, max_length=0):
                    seen.append(max_length)
                    out = d.decompress(data, max_length)
                    seen.append(len(out))
                    return out

                def __getattr__(self, name):
                    return getattr(d, name)
            return Wrap()
        with unittest.mock.patch.object(wb.zlib, "decompressobj", spy):
            with self.assertRaises(wb.Refused):
                wb.decode(text)
        self.assertEqual(seen[0], wb.MAX_PAYLOAD + 1, "decompression is asked for at most the bound plus one")
        self.assertLessEqual(seen[1], wb.MAX_PAYLOAD + 1, "never more than the bound plus one is produced")
        with self.assertRaises(wb.Refused):
            wb.decode("x" * (wb.MAX_REPORT + 1))

    def test_an_existing_import_is_never_overwritten_and_a_bad_label_is_refused(self):
        wb.import_bundle(make_bundle(), "exit-x", self.root)
        before = (self.root / "exit-x" / "windows" / "tests.txt").read_text()
        with self.assertRaises(wb.Refused):
            wb.import_bundle(make_bundle({"tests.txt": "### t\ntest b ... ok\n### t exit=0\n"}), "exit-x", self.root)
        self.assertEqual((self.root / "exit-x" / "windows" / "tests.txt").read_text(), before)
        for bad in ("", "../up", "a/b", ".hidden", "-x"):
            with self.assertRaises(wb.Refused):
                wb.import_bundle(make_bundle(), bad, self.root)

    def test_a_config_whose_artifacts_root_is_elsewhere_is_refused_before_writing(self):
        cfg_path = Path(self.tmp.name) / "runs.json"
        cfg_path.write_text(json.dumps({"artifacts_root": str(Path(self.tmp.name) / "other"), "platforms": {}}))
        with self.assertRaises(wb.Refused):
            wb.import_bundle(make_bundle(), "exit-x", self.root, config=cfg_path)
        self.assertFalse((self.root / "exit-x" / "windows").exists())

    def test_the_powershell_runner_selftest_bundle_imports(self):
        # The runner's own bundle writer (run-windows-local.ps1 -SelfTest), when PowerShell 7
        # is installed here; a skip otherwise.
        import shutil
        pwsh = shutil.which("pwsh")
        if not pwsh:
            self.skipTest("pwsh is not installed on this host")
        out = Path(self.tmp.name) / "ps"
        r = subprocess.run([pwsh, "-NoProfile", "-File", str(HERE / "run-windows-local.ps1"), "-SelfTest", "-Out", str(out)],
                           capture_output=True, text=True, timeout=300)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("0 failed", r.stdout)
        dest, _, n = wb.import_bundle((out / "bundle.b64").read_text(), "exit-ps", self.root, commit="0" * 40)
        tests = (dest / "tests.txt").read_text()
        self.assertGreaterEqual(n, 3)
        for value in ("fixtureuser", "FIXTUREHOST", "wslfixture", "HEIMDALL_CANARY_", "3333333333", "203.0.113.9"):
            self.assertNotIn(value.lower(), "".join(p.read_text() for p in dest.iterdir()).lower(), value)
        self.assertIn("<canary>", tests)
        self.assertIn("observation selftest=1", tests)


class PlatformTests(unittest.TestCase):
    def sym(self, crate, path, disambiguator="s1a_"):
        out = "_RNv" + "Nt" * (len(path) - 1) + "C" + disambiguator + pt.ident(crate)
        for part in path:
            out += pt.ident(part)
        return out.encode()

    def test_identifier_encoding_and_decoding(self):
        self.assertEqual(pt.ident("abc"), "3abc")
        self.assertEqual(pt.ident("_x"), "2__x")
        self.assertEqual(pt.parse_ident(b"3abc", 0), ("abc", 4))
        self.assertEqual(pt.parse_ident(b"2__x", 0), ("_x", 4))
        self.assertEqual(pt.parse_ident(b"s0_3abc", 0), ("abc", 7), "a disambiguator is skipped")
        self.assertIsNone(pt.parse_ident(b"3ab", 0), "too short")
        self.assertIsNone(pt.parse_ident(b"x", 0))

    def test_function_paths_read_only_the_named_crate(self):
        data = b"\0junk" + self.sym("mycrate", ["mod_a", "test_one"]) + b"\0" + self.sym("mycrate", ["test_top"]) + b"\0" \
            + self.sym("othercrate", ["mod_a", "test_two"]) + b"\0_RNvCsXX_5alien4junk\0"
        paths = pt.function_paths(data, "mycrate")
        self.assertEqual(paths, {("mod_a", "test_one"), ("test_top",)})

    def test_source_test_names_find_test_functions_only(self):
        with tempfile.TemporaryDirectory(prefix="m02src") as d:
            d = Path(d)
            (d / "tests").mkdir()
            (d / "crates").mkdir()
            (d / "tests" / "a.rs").write_text(
                "#[test]\nfn one() {}\n#[tokio::test]\nasync fn two() {}\n#[test]\n#[ignore]\npub fn three() {}\nfn helper() {}\n"
            )
            self.assertEqual(pt.source_test_names(d), {"one", "two", "three"})

    def test_compression_is_faithful_over_random_platform_assignments(self):
        rng = random.Random(0x4D3032)
        plats = ["macos", "linux", "windows"]
        for case in range(300):
            names = []
            for m in range(rng.randint(0, 3)):
                for i in range(rng.randint(1, 4)):
                    names.append(f"mod{m}::t{i}")
                    if rng.random() < 0.3:
                        names.append(f"mod{m}::inner::u{i}")
            names += [f"top{i}" for i in range(rng.randint(0, 4))]
            if not names:
                continue
            where = {n: set(rng.sample(plats, rng.randint(1, 3))) for n in names}
            entries = pt.compress("tgt", where, plats)
            index = {"platform_only": entries}
            for n in names:
                for p in plats:
                    allowed = ev.platform_only_lookup(index, {}, "tgt", n)
                    got = True if allowed is None else p in allowed
                    self.assertEqual(got, p in where[n], (case, n, p, entries))

    def test_platform_only_combines_scans_with_the_build_host_listing(self):
        with tempfile.TemporaryDirectory(prefix="m02plat") as d:
            d = Path(d)
            (d / "t.txt").write_text("a\nb\nm::c\n")
            reports = {"windows": {"t": {"present": 2, "absent": ["m::c"], "extra": ["win_only"]}}}
            entries, extra = pt.platform_only("macos", d, reports)
            self.assertEqual(extra, {"t": {"win_only": ["windows"]}})
            index = {"platform_only": entries}
            self.assertEqual(ev.platform_only_lookup(index, {}, "t", "m::c"), ["macos"])
            self.assertIsNone(ev.platform_only_lookup(index, {}, "t", "a"))


# --- pty-answer.py -------------------------------------------------------------------------


class PtyAnswer(unittest.TestCase):
    def run_pty(self, timeout, *program):
        with tempfile.TemporaryDirectory(prefix="m02pty") as d:
            t = Path(d) / "transcript"
            r = subprocess.run(
                [sys.executable, "-I", str(HERE / "pty-answer.py"), str(t), "yes", str(timeout), "--", *program],
                capture_output=True, text=True, timeout=60,
            )
            return r.returncode, (t.read_text(errors="replace") if t.exists() else ""), r.stderr

    def test_a_typed_yes_answers_each_prompt_once_and_the_programs_exit_is_returned(self):
        script = 'printf "first [y/N] "; read a; printf "got:%s\\n" "$a"; printf "second [y/N] "; read b; printf "got:%s\\n" "$b"; exit 7'
        rc, transcript, _ = self.run_pty(20, "/bin/sh", "-c", script)
        self.assertEqual(rc, 7)
        self.assertEqual(transcript.count("got:yes"), 2, transcript)

    def test_a_program_that_never_prompts_is_not_typed_at(self):
        rc, transcript, _ = self.run_pty(20, "/bin/sh", "-c", "echo plain; exit 0")
        self.assertEqual(rc, 0)
        self.assertIn("plain", transcript)
        self.assertNotIn("yes", transcript)

    def test_a_program_that_does_not_exit_in_time_is_killed_with_124(self):
        rc, _, _ = self.run_pty(1, "/bin/sh", "-c", "sleep 30")
        self.assertEqual(rc, 124)

    def test_a_signal_death_is_128_plus_the_signal(self):
        rc, _, _ = self.run_pty(20, "/bin/sh", "-c", "kill -TERM $$")
        self.assertEqual(rc, 128 + 15)

    def test_bad_usage_is_2(self):
        r = subprocess.run([sys.executable, "-I", str(HERE / "pty-answer.py"), "t", "yes"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)

    def test_a_missing_program_is_127(self):
        rc, _, _ = self.run_pty(20, "/nonexistent/hm-m02-no-such-program")
        self.assertEqual(rc, 127)


# --- the committed files -------------------------------------------------------------------

# m02-plan section 3 and 4: the cases, their platform rows and the owner inputs that block rows.
EXPECTED_DECLARED = {
    "A01": {"macos", "linux", "windows", "wsl-distro"},
    "A11": {"macos", "linux", "windows"},
    "A21": {"macos", "linux", "windows"},
    "A22": {"macos", "linux", "windows", "wsl-distro"},
    "A27": {"macos", "linux", "windows"},
    "A35": {"macos", "linux", "windows", "wsl-distro"},
    "R-RT-05": {"macos", "linux", "windows"},
    "ADR-0006-13.20-3": {"macos", "linux", "windows"},
    "R-SE-04": {"macos", "linux", "windows"},
    "T06": {"macos", "linux", "windows", "wsl-distro"},
}
EXPECTED_CLAIMS = {
    "A participant can connect without a mandatory work wrapper": {"wsl-distro"},
    "No remote authentication change, key export, or provider-policy bypass was needed": {"macos", "linux", "windows"},
    "Does not claim managed unattended access until M03": {"macos", "linux", "windows"},
}
# ADR-0007 §12.45: an owner-input row whose input is now satisfied but whose native test does not
# exist yet is deferred with a recorded decision (not counted), never left "blocked".
EXPECTED_DEFERRED_ROWS = {"A22": {"windows-11 file-symlink reparse-point row"}}

EXPECTED_BLOCKED_INPUTS = {
    "A01": {"B2", "B3", "B9"},
    "A11": {"B1", "B4", "B6"},
    "A27": {"B5"},
    "A35": {"B1", "B4", "B9"},
    "A participant can connect without a mandatory work wrapper": {"B7"},
}


# Declared rows with no applicable test. Before ADR-0007 §12.32 item 4 the T06 uninstall tests
# were Unix-only CLI end-to-end tests (tests/e2e/cli_m02.rs `unix` module) and the Windows row
# had no test of its own (the generator records it `no_applicable_test`, in_progress). Since
# item 4 `json::uninstall_restores_...` runs on every platform, so an inventory regenerated
# from those sources closes the gap; one generated before still shows it.
KNOWN_ROW_GAPS = {("T06", "windows"): "the uninstall end-to-end tests are cfg(unix)"}


def t06_cli_runs_everywhere(inv):
    """Whether the inventory was generated after §12.32 item 4 (its T06 CLI tests include the
    cross-platform `json::` module)."""
    return any(n.startswith("json::") for n in inv["groups"]["T06"]["tests"].get("e2e_cli_m02", []))


def known_row_gaps(inv):
    return {} if t06_cli_runs_everywhere(inv) else KNOWN_ROW_GAPS


class RealFiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = json.loads((HERE / "case-index.json").read_text(encoding="utf-8"))
        cls.cfg = json.loads((HERE / "runs.json").read_text(encoding="utf-8"))
        cls.plan = (ROOT / "docs" / "architecture" / "m02-plan.md").read_text(encoding="utf-8")
        inv_path = HERE / "required-inventory.json"
        cls.inv = json.loads(inv_path.read_text(encoding="utf-8")) if inv_path.exists() else None
        sec3 = cls.plan.split("## 3. Milestone exit mapping", 1)[1].split("## 4. Platform evidence plan", 1)[0]
        cls.sec3 = sec3

    def test_every_m02_plan_section_3_case_and_claim_is_indexed(self):
        for case in EXPECTED_DECLARED:
            token = case.replace("ADR-0006-13.20-3", "ADR-0006 §13.20 item 3")
            self.assertIn(token, self.sec3, f"{case} is a row of m02-plan section 3")
            self.assertIn(case, self.index["groups"], f"{case} is in the case index")
        for claim in EXPECTED_CLAIMS:
            self.assertIn(claim, self.index["exit_claims"], claim)
            if claim.startswith("Does not claim"):
                self.assertIn(claim, self.sec3)
        self.assertEqual(set(self.index["groups"]), set(EXPECTED_DECLARED), "no case beyond section 3")
        aggregate = self.index["exit_claims"]["M02 exit cases (m02-plan §3)"]
        self.assertEqual(set(aggregate["groups"]), set(self.index["groups"]), "the aggregate covers every group")

    def test_declared_platform_rows_follow_the_section_4_table(self):
        for case, want in EXPECTED_DECLARED.items():
            self.assertEqual(set(self.index["groups"][case]["declared_platforms"]), want, case)
        for claim, want in EXPECTED_CLAIMS.items():
            self.assertEqual(set(self.index["exit_claims"][claim]["declared_platforms"]), want, claim)
        self.assertEqual(set(self.index["platforms"]), {"macos", "linux", "windows", "wsl-distro"})
        self.assertEqual(self.index["platforms"]["wsl-distro"]["runs"], "scenario")
        self.assertEqual(self.index["build_host"], "macos")

    def test_blocked_rows_name_exactly_the_owner_inputs_of_section_4(self):
        seen = {}
        deferred = {}
        for sid, sec in list(self.index["groups"].items()) + list(self.index["exit_claims"].items()):
            for row in sec.get("blocked_rows", []):
                if row["status"] == "deferred_with_decision":
                    self.assertRegex(row.get("decision", ""), r"^ADR-0007 §12\.\d+: \S", (sid, row))
                    self.assertNotIn("blocked_on", row, (sid, row))
                    deferred.setdefault(sid, set()).add(row["platform"])
                    continue
                self.assertEqual(row["status"], "blocked", (sid, row))
                m = re.match(r"^(B\d+): \S", row.get("blocked_on", ""))
                self.assertIsNotNone(m, f"{sid}: blocked row names no B-input: {row}")
                seen.setdefault(sid, set()).add(m.group(1))
                self.assertRegex(self.plan, rf"\| {m.group(1)}[ |]", f"{m.group(1)} is in m02-plan section 7")
        self.assertEqual(seen, EXPECTED_BLOCKED_INPUTS)
        self.assertEqual(deferred, EXPECTED_DEFERRED_ROWS)

    def test_every_scenario_step_has_a_description_and_a_source_file(self):
        for name, sc in self.index["scenario_targets"].items():
            self.assertTrue(set(sc["platforms"]) <= set(self.index["platforms"]), name)
            self.assertTrue((ROOT / sc["source"]).is_file(), f"{name}: {sc['source']}")
            self.assertTrue(sc["steps"], name)
            for step, text in sc["steps"].items():
                self.assertTrue(text.strip(), f"{name}::{step}")
        ordinary = self.index["scenario_targets"]["wsl_ordinary_ssh"]
        script = (HERE / "scenario-ordinary-ssh.sh").read_text(encoding="utf-8")
        for step in ordinary["steps"]:
            self.assertIn(f"step {step} ", script, f"the scenario script reports {step}")
        for m in re.finditer(r"^step (\w+) ", script, re.M):
            self.assertIn(m.group(1), ordinary["steps"], f"the scenario reports an undeclared step {m.group(1)}")

    def test_windows_launch_rows_match_the_driver(self):
        rows = set(self.index["scenario_targets"]["windows_launch"]["steps"])
        driver = (ROOT / "tests" / "native" / "windows-launch" / "Invoke-WindowsLaunch.ps1").read_text(encoding="utf-8")
        forms = re.search(r"foreach \(\$form in @\(([^)]*)\)\)", driver)
        self.assertIsNotNone(forms, "the driver loops over the Ctrl-C forms")
        reported = {"ctrlc." + f for f in re.findall(r"'(\w+)'", forms.group(1))}
        if "Add-Row 'resize'" in driver:
            reported.add("resize")
        self.assertEqual(reported, rows, "the case index lists exactly the rows the driver reports")

    def test_build_host_path_entries_are_well_formed_and_point_at_real_sources(self):
        for key, meta in self.index["build_host_paths"].items():
            self.assertIsInstance(meta["neutral"], bool, key)
            self.assertTrue(meta["reason"].strip(), key)

    def test_child_entries_are_ignored_entry_points_in_the_sources(self):
        for key in self.index["child_entries"]:
            leaf = key.rsplit("::", 1)[-1]
            hits = []
            for base in ("tests", "crates"):
                for p in (ROOT / base).rglob("*.rs"):
                    if "target" in p.parts:
                        continue
                    text = p.read_text(encoding="utf-8", errors="replace")
                    if re.search(rf"#\[ignore[^\]]*\][^{{}}]*?fn {leaf}\b", text, re.S):
                        hits.append(p)
            self.assertTrue(hits, f"{key}: no #[ignore]d fn {leaf} in the sources")

    def test_runs_json_has_one_record_per_group_and_claim_with_valid_ids(self):
        recs = self.cfg["records"]
        wanted = set(self.index["groups"]) | set(self.index["exit_claims"])
        self.assertEqual(set(recs), wanted)
        case_ids = [r["case_id"] for r in recs.values()]
        paths = [r["path"] for r in recs.values()]
        self.assertEqual(len(set(case_ids)), len(case_ids))
        self.assertEqual(len(set(paths)), len(paths))
        for sid, meta in recs.items():
            self.assertRegex(meta["path"], r"^tests/evidence/m02-[a-z0-9-]+\.json$", sid)
            for rid in meta["requirement_ids"]:
                self.assertRegex(rid, r"^R-[A-Z]{2}-0[1-8]$", sid)
            self.assertTrue(meta["summary"].strip())
        for gid, g in self.index["groups"].items():
            self.assertEqual(recs[gid]["requirement_ids"], g["requirement_ids"], gid)
        union = {r for g in self.index["groups"].values() for r in g["requirement_ids"]}
        self.assertEqual(set(recs["M02 exit cases (m02-plan §3)"]["requirement_ids"]), union)

    def test_runs_json_configures_every_declared_platform_with_logs_commands_and_facts(self):
        declared = set()
        for sec in list(self.index["groups"].values()) + list(self.index["exit_claims"].values()):
            declared.update(sec.get("declared_platforms", []))
        self.assertEqual(set(self.cfg["platforms"]), declared)
        for name, p in self.cfg["platforms"].items():
            for key in ("label", "logs", "commands_logs", "facts"):
                self.assertTrue(p.get(key), f"{name}.{key}")
            for rel in p["logs"] + p["commands_logs"] + p["facts"]:
                self.assertFalse(rel.startswith(("/", "..")), f"{name}: artifact paths are relative to artifacts_root")
        self.assertEqual(self.cfg["case_index"], "tests/native/m02/case-index.json")
        self.assertTrue((ROOT / self.cfg["case_index"]).is_file())
        for rel in self.cfg["evidence_paths"]:
            self.assertTrue((ROOT / rel).is_file(), rel)

    def test_no_native_run_is_claimed_before_one_exists(self):
        # The committed config is a template: no build commit, no start time, no artifacts.
        self.assertIsNone(self.cfg["build_commit"])
        self.assertIsNone(self.cfg["started_at"])
        for p in self.cfg["platforms"].values():
            self.assertIsNone(p["artifact_digest"])
        for m in ev.ROOT.glob("tests/evidence/m02-*.json"):
            rec = json.loads(m.read_text(encoding="utf-8"))
            self.assertEqual(ev.validate_record(rec), [], m.name)

    def test_observation_targets_cover_every_source_that_prints_observations(self):
        listed = set(self.index["observation_targets"])
        self.assertEqual(len(listed), len(self.index["observation_targets"]), "no duplicates")
        printers = set()
        for p in (ROOT / "tests").rglob("*.rs"):
            if "target" in p.parts or p.parent == ROOT / "tests":
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
            if re.search(r'^\s*"observation[ :]', text, re.M):
                printers.add(f"{p.parent.name}_{p.stem}")
        self.assertTrue(printers, "the scan finds the observation printers")
        self.assertEqual(printers, listed, "case-index.json observation_targets must list every target that prints observation lines")

    def test_the_remote_harnesses_run_every_binary_with_show_output(self):
        for script, marker in (("run-linux.sh", 'set -- "$@" --show-output'), ("run-windows.sh", 'set -- "$@" --show-output')):
            text = (HERE / script).read_text(encoding="utf-8")
            self.assertIn(marker, text, script)
        mac = (HERE / "run-macos.sh").read_text(encoding="utf-8")
        self.assertIn("-- --show-output", mac)
        self.assertIn("observation_targets", mac)

    def test_a_dry_run_over_the_real_index_writes_valid_records_and_keeps_the_invariants(self):
        """Every required test passes in synthetic logs (minus what the remote harnesses cannot
        run); the real index, inventory and runs.json must still produce schema-valid records
        in which a blocked owner-input row blocks the record and a harness gap or an empty
        platform row is never verified."""
        self.assertIsNotNone(self.inv)
        index, inv, cfg = copy(self.index), copy(self.inv), copy(self.cfg)
        with tempfile.TemporaryDirectory(prefix="m02dry") as tmp:
            d = Path(tmp)
            (d / "src" / "tests").mkdir(parents=True)
            (d / "src" / "tests" / "a.rs").write_text("fn a() {}\n")
            inv["sources_sha256"] = ev.sources_digest(d / "src")
            (d / "index.json").write_text(json.dumps(index))
            (d / "inventory.json").write_text(json.dumps(inv))
            for pname, p in cfg["platforms"].items():
                logs = {}
                for kind, sid, spec, _ in ev.sections(index):
                    for t, n in ev.required(index, inv, kind, sid, pname):
                        if pname != index["build_host"] and ev.build_host_path(index, t, n):
                            continue
                        logs.setdefault(t, {})[n] = "ok"
                (d / f"{pname}.log").write_text(log_text(logs, "harness"))
                (d / f"{pname}.commands").write_text("exit 0: the run\n")
                (d / f"{pname}.facts").write_text("os=synthetic\n")
                p.update(logs=[f"{pname}.log"], commands_logs=[f"{pname}.commands"], facts=[f"{pname}.facts"],
                         artifact_digest="n/a")
            paths = {}
            for sid, meta in cfg["records"].items():
                paths[sid] = d / (re.sub(r"[^a-z0-9]+", "-", meta["case_id"].lower()) + ".json")
                meta["path"] = str(paths[sid])
            cfg.update(case_index=str(d / "index.json"), required_inventory=str(d / "inventory.json"),
                       sources_root=str(d / "src"), summary_out=str(d / "summary.json"), artifacts_root=str(d),
                       build_commit="0" * 40, started_at="2026-11-04T00:00:00+00:00", artifact_digest="n/a")
            (d / "runs.json").write_text(json.dumps(cfg))
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = ev.main(["--config", str(d / "runs.json"), "--write"])
            self.assertEqual(rc, 0, err.getvalue()[:600])
            summary = json.loads((d / "summary.json").read_text())
            self.assertEqual(sorted(p.name for p in d.glob("*.json") if p.name not in
                                    ("index.json", "inventory.json", "summary.json", "runs.json")),
                             sorted(p.name for p in paths.values()), "one record per case and claim")
            for sid, path in paths.items():
                rec = json.loads(path.read_text())
                self.assertEqual(ev.validate_record(rec), [], sid)
                sec = index["groups"].get(sid) or index["exit_claims"][sid]
                rows = rec["observed_result"]["rows"]
                if any(r.get("status") == "blocked" for r in rows):
                    self.assertEqual(rec["status"], "blocked", sid)
                    self.assertRegex(rec["blocked_on"], r"B\d+: ", sid)
                for r in rows:
                    if r.get("harness_gap_not_run") or r.get("no_applicable_test") or r.get("incomplete_run"):
                        self.assertNotIn(r["status"], ("verified", "blocked"), (sid, r["platform"]))
                if any(r["status"] == "blocked" for r in sec.get("blocked_rows", [])):
                    self.assertEqual(rec["status"], "blocked", f"{sid} has an owner-input row")
            t06 = [r for r in summary["groups"]["T06"]["rows"] if r["platform"].startswith("windows")][0]
            if t06_cli_runs_everywhere(inv):
                # §12.32 item 4: `json::uninstall_*` applies on Windows, so the row has a test.
                self.assertNotIn("no_applicable_test", t06)
            else:
                # The Windows row of T06 has no applicable test: a recorded gap, not a pass.
                self.assertEqual(t06["status"], "in_progress")
                self.assertIn("no_applicable_test", t06)

    def test_the_a21_record_never_calls_the_executed_construct_list_complete(self):
        meta = self.cfg["records"]["A21"]
        self.assertIn("constructs found before execution", meta["summary"])
        self.assertIn("never complete", meta["summary"])
        self.assertIn("constructs found before execution", self.index["groups"]["A21"]["evidence_wording"])
        self.assertIn("two observed snapshots", self.index["groups"]["A21"]["evidence_wording"])

    def test_the_committed_inventory_matches_the_case_index_structure(self):
        self.assertIsNotNone(self.inv, "tests/native/m02/required-inventory.json is committed")
        problems = ev.check_inventory(self.index, self.inv)
        self.assertEqual(problems, [], "regenerate with refresh-inventory.sh: " + "; ".join(problems[:5]))
        self.assertEqual(self.inv["build_host"], "macos")
        self.assertEqual(sorted(self.inv["scanned_platforms"]), ["linux", "windows"],
                         "the inventory carries the cfg scans of both cross-built targets")
        for sid, sec in {**self.inv["groups"], **self.inv["exit_claims"]}.items():
            for target, names in sec["tests"].items():
                self.assertEqual(names, sorted(set(names)), f"{sid}.{target} is sorted and unique")

    def test_inventory_names_are_defined_in_the_sources(self):
        self.assertIsNotNone(self.inv)
        defined = set()
        for base in ("tests", "crates"):
            for p in (ROOT / base).rglob("*.rs"):
                if "target" not in p.parts:
                    defined.update(re.findall(r"\bfn\s+(\w+)", p.read_text(encoding="utf-8", errors="replace")))
        scenario = set(self.index["scenario_targets"])
        missing = []
        for kind in ("groups", "exit_claims"):
            for sid, sec in self.inv[kind].items():
                for target, names in sec["tests"].items():
                    if target in scenario:
                        continue
                    for n in names:
                        if n.rsplit("::", 1)[-1] not in defined:
                            missing.append(f"{sid}: {target}::{n}")
        self.assertEqual(missing, [], "tests the inventory requires that no source defines (regenerate): " + "; ".join(missing[:5]))

    def test_declared_rows_without_an_applicable_test_are_exactly_the_known_gaps(self):
        """A platform row m02-plan section 4 declares must have a test that applies on it, or
        be a recorded gap (the generator then reports it `no_applicable_test`, in_progress,
        never verified). A new gap or a closed one needs a conscious update here."""
        self.assertIsNotNone(self.inv)
        gaps = {}
        for kind in ("groups", "exit_claims"):
            for sid, sec in self.index[kind].items():
                if "tests" not in sec:
                    continue
                for plat in sec.get("declared_platforms", []):
                    if not ev.required(self.index, self.inv, kind, sid, plat):
                        gaps[(sid, plat)] = True
        self.assertEqual(set(gaps), set(known_row_gaps(self.inv)), "the declared rows with no applicable test changed")

    def test_the_cli_end_to_end_suites_are_the_unix_only_reason_for_the_known_gap(self):
        self.assertIsNotNone(self.inv)
        windows_cli = [n for n in self.inv["groups"]["T06"]["tests"].get("e2e_cli_m02", [])
                       if ev.applicable(self.index, self.inv, "e2e_cli_m02", n, "windows")]
        if t06_cli_runs_everywhere(self.inv):
            # §12.32 item 4: the --json uninstall case applies on Windows, the pty ones do not.
            self.assertTrue(windows_cli, "json::uninstall_* applies on Windows")
            self.assertTrue(all(n.startswith("json::") for n in windows_cli), windows_cli)
        else:
            self.assertEqual(windows_cli, [], "if a T06 CLI test starts to apply on Windows, drop the known gap")


if __name__ == "__main__":
    unittest.main(verbosity=2)
