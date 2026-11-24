#!/usr/bin/env python3
"""M07-U9: generator dry runs over synthetic logs, run by tests/native/m07/selftest.sh.

Reaches no host and builds nothing. The real case index (tests/native/m07/case-index.json), the
runs template (runs.json) and the committed required inventory (required-inventory.json) are the
inputs; every log is synthesized from them in a temporary directory, so a run here proves what the
generator does with *this* index (tests/native/m06/selftest_synthetic.py, the same method). The
inventory is re-stamped with the temporary sources' digest, and the case index is reduced to the
targets the committed inventory holds (HM_SKIP_TARGETS semantics). Records are written only into
the temporary directory, never into tests/evidence/.

What is pinned:
  * a run in which every required test passes: every declared platform row of every case is
    verified; the case index's rows for what is not built yet (revision 7) keep their cases
    blocked with the reason named; the deferred row stays deferred and never counts; A30 is
    blocked on B14 and B7; the records validate against tests/evidence/record.schema.json;
  * a required test missing from a platform that ran, a failed test and a nonzero required
    command: that platform's rows are in_progress, never verified and never blocked;
  * a platform that did not run: its rows are blocked with the exact missing platform named;
  * the index's own rows: blocked stays blocked with its blocked_on, deferred_with_decision stays
    deferred, and a row the index claims verified or in_progress, or one without its reason, is
    refused (nothing is written);
  * A30 is never reported passing: not without an A30 group, not with an A30 group whose every
    test passed, not in an exit claim that lists it, not in the exit record that does not;
  * `m07 observation:` lines reach the row of the test that printed them;
  * HM_SKIP_TARGETS refuses --write; no unit target is selected with a feature;
  * the committed index, runs template and inventory agree with one another.
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


def load_m07():
    argv = sys.argv
    spec = importlib.util.spec_from_file_location("m07_evidence", HERE / "m07-evidence.py")
    mod = importlib.util.module_from_spec(spec)
    sys.argv = ["m07-evidence.py"]
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.argv = argv
    return mod


m07 = load_m07()
ev = m07.ev
INDEX = json.loads((HERE / "case-index.json").read_text(encoding="utf-8"))
INV = json.loads((HERE / "required-inventory.json").read_text(encoding="utf-8"))
RUNS = json.loads((HERE / "runs.json").read_text(encoding="utf-8"))

PLATFORMS = ("macos", "linux", "windows")
GROUPS = list(INDEX["groups"])
A30 = "A30"
A30_REASON = m07.OWNER_BLOCKED[A30]["blocked_on"]
EXIT_KEY = "M07 exit cases (m07-plan §6)"


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
    return m07.m05.drop_targets(copy.deepcopy(INDEX), {t for t in named if t not in have})


def log_text(targets, style, observations=None):
    """A platform's log, as libtest prints it (observations under `---- <test> stdout ----`)."""
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
    """{platform: {target: {test: "ok"}}}: every test the index requires on each platform passes."""
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


def with_exit_claim(index, groups=None):
    """The index with M07's exit claim over the given groups (default: every group)."""
    index = copy.deepcopy(index)
    index["exit_claims"][EXIT_KEY] = {"groups": list(GROUPS if groups is None else groups)}
    return index


EXIT_RECORD = {
    "case_id": m07.EXIT_CASE_ID,
    "path": "tests/evidence/m07-exit-claims.json",
    "requirement_ids": ["R-UX-05"],
    "summary": "synthetic exit record",
    "limitations": [],
}


class Scratch:
    """A temporary index, inventory, logs and config; runs the generator's main()."""

    def __init__(self, testcase, index=None, logs=None, platforms=None, observations=None, inv=None,
                 commands=None, records=None):
        self.tmp = tempfile.TemporaryDirectory(prefix="m07ev")
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
            started_at="2026-11-24T00:00:00+00:00",
            commands=["synthetic"],
            evidence_paths=["synthetic"],
        )
        for pname in PLATFORMS:
            style = "cargo" if pname == "macos" else "harness"
            (d / f"{pname}.log").write_text(log_text(self.logs.get(pname, {}), style, (observations or {}).get(pname)))
            (d / f"{pname}.commands").write_text((commands or {}).get(pname, "exit 0: the required command\n"))
            (d / f"{pname}.facts").write_text("os=synthetic\nsecret-thing=must not be kept\n")
            cfg["platforms"][pname].update(
                logs=[f"{pname}.log"], commands_logs=[f"{pname}.commands"], facts=[f"{pname}.facts"],
                artifact_digest="n/a",
            )
        for pname, upd in (platforms or {}).items():
            cfg["platforms"][pname].update(upd)
        if records is not None:
            cfg["records"] = copy.deepcopy(records)
        self.record_paths = {}
        for sid, rec in cfg["records"].items():
            rec["path"] = str(d / "out" / Path(rec["path"]).name)
            self.record_paths[sid] = Path(rec["path"])
        (d / "out").mkdir()
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

    def written(self):
        return sorted(p.name for p in (self.dir / "out").iterdir())


def rows(summary, sid, kind="groups"):
    return summary[kind][sid]["rows"]


def row(summary, sid, plat):
    """The one platform row of a case (the index's own rows carry their own labels)."""
    label = RUNS["platforms"][plat]["label"]
    found = [r for r in rows(summary, sid) if r["platform"] == label]
    assert len(found) == 1, (sid, plat, found)
    return found[0]


def declared(index, sid):
    return [p for p in index["groups"][sid].get("declared_platforms", []) if p in PLATFORMS]


def a_test(index, sid, plat):
    """(target, name) of one test the case requires on the platform."""
    for target, name in ev.required(index, INV, "groups", sid, plat):
        return target, name
    raise AssertionError(f"{sid} requires nothing on {plat}")


def index_gaps(index, inv):
    """{(case, platform): reason} for the declared rows the case index itself leaves short of
    verified even when every test passes: a required test the inventory scan finds absent on a
    platform with no case-index platform_only rationale, or a declared platform on which no
    indexed test applies (its only tests are platform_required names, which are never resolved
    into the inventory)."""
    out = {}
    for sid, sec in index["groups"].items():
        for plat in declared(index, sid):
            guard = ev.coverage_guard(index, inv, "groups", sid, plat, {})
            if absent_required(index, inv, sid, plat):
                out[(sid, plat)] = "platform_required names a test the scan finds absent there"
            elif guard["unjustified"]:
                out[(sid, plat)] = "excluded_without_rationale"
            elif not ev.required(index, inv, "groups", sid, plat):
                out[(sid, plat)] = "no_applicable_test"
    return out


def absent_required(index, inv, sid, plat):
    """The platform_required names of a case on a platform that the inventory scan finds absent
    there (`#[cfg]` removes them): a row that names one can never pass."""
    req = (index["groups"][sid].get("platform_required") or {}).get(plat) or {}
    out = []
    for target, names in req.items():
        for n in names:
            where = inv.get("platform_only", {}).get(f"{target}::{n}")
            if where is not None and plat in inv.get("scanned_platforms", []) and plat not in where:
                out.append(f"{target}::{n}")
    return out


def completed(index, inv):
    """(index, inventory) with the index_gaps closed as the integrator would close them: a
    platform_required name the scan finds absent on its platform dropped, a rationale for every
    scan-only exclusion, and each platform_required name of a platform with
    no applicable indexed test indexed as a test of its case (a platform-only extra there, as a
    regenerated inventory would hold it). Used to show every declared row verified."""
    index, inv = copy.deepcopy(index), copy.deepcopy(inv)
    for sid, sec in index["groups"].items():
        for plat in declared(index, sid):
            drop = set(absent_required(index, inv, sid, plat))
            req = (sec.get("platform_required") or {}).get(plat)
            for target in list(req or {}):
                req[target] = [n for n in req[target] if f"{target}::{n}" not in drop]
                if not req[target]:
                    del req[target]
            guard = ev.coverage_guard(index, inv, "groups", sid, plat, {})
            for qual in guard["unjustified"]:
                index["platform_only"][qual] = {"platforms": inv["platform_only"][qual],
                                                "rationale": "synthetic: the selftest's completed index"}
    for sid, sec in index["groups"].items():
        for plat in declared(index, sid):
            if ev.required(index, inv, "groups", sid, plat):
                continue
            for target, names in ((sec.get("platform_required") or {}).get(plat) or {}).items():
                spec = sec["tests"].setdefault(target, [])
                sec["tests"][target] = sorted(set(spec) | set(names))
                extra = inv["platform_extra"].setdefault(sid, {}).setdefault(plat, {}).setdefault(target, [])
                extra[:] = sorted(set(extra) | set(names))
                for n in names:
                    inv["platform_only"][f"{target}::{n}"] = [plat]
                    index["platform_only"][f"{target}::{n}"] = {"platforms": [plat],
                                                               "rationale": "synthetic: the selftest's completed index"}
    return index, inv


def without_index_rows(index, keep=()):
    """The index with every case's own rows removed except those whose status is in keep."""
    index = copy.deepcopy(index)
    for sec in index["groups"].values():
        if "blocked_rows" in sec:
            sec["blocked_rows"] = [r for r in sec["blocked_rows"] if r["status"] in keep]
    return index


def with_tested_a30(index, inv):
    """(index, inventory) with an A30 group whose tests are CLI-standalone's (a stand-in for
    U2a's deterministic checks, which the case index does not hold yet)."""
    index, inv = copy.deepcopy(index), copy.deepcopy(inv)
    sec = copy.deepcopy(index["groups"]["CLI-standalone"])
    sec["title"] = "A30 (synthetic): U2a's deterministic part"
    sec.pop("platform_required", None)
    index["groups"][A30] = sec
    inv["groups"][A30] = copy.deepcopy(inv["groups"]["CLI-standalone"])
    return index, inv


class CleanRun(unittest.TestCase):
    def test_every_required_test_passing_verifies_every_declared_platform_row(self):
        index, inv = completed(reduced_index(), INV)
        self.assertEqual(index_gaps(index, inv), {})
        s = Scratch(self, index=index, inv=inv)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        for sid in GROUPS:
            for plat in declared(index, sid):
                r = row(summary, sid, plat)
                self.assertEqual(r["status"], "verified", (sid, plat, r))
                self.assertGreater(r["passed"], 0, (sid, plat))
            ran = [r for r in rows(summary, sid) if r["platform"] in {RUNS["platforms"][p]["label"] for p in PLATFORMS}]
            self.assertEqual({r["status"] for r in ran}, {"verified"}, sid)
        self.assertEqual(summary["groups"]["CLI-standalone"]["status"], "verified")
        self.assertEqual(summary["groups"]["A20"]["status"], "verified")

    def test_with_the_committed_index_a_row_it_leaves_short_is_in_progress_never_verified(self):
        # ⟨W9c⟩ The committed index leaves some Windows rows short (DONE lists them): every test
        # passing must not verify them, and every other declared row is verified.
        s = Scratch(self)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        gaps = index_gaps(s.index, s.inv)
        for sid in GROUPS:
            for plat in declared(s.index, sid):
                r = row(summary, sid, plat)
                if (sid, plat) in gaps:
                    self.assertEqual(r["status"], "in_progress", (sid, plat, r))
                    self.assertTrue({"excluded_without_rationale", "no_applicable_test", "platform_required_not_passed"} & set(r),
                                    (sid, plat, gaps[(sid, plat)], r))
                else:
                    self.assertEqual(r["status"], "verified", (sid, plat, r))

    def test_the_rows_not_built_yet_keep_their_cases_blocked_with_the_reason_named(self):
        s = Scratch(self)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        for sid in GROUPS:
            for want in INDEX["groups"][sid].get("blocked_rows", []):
                got = [r for r in rows(summary, sid) if r["platform"] == want["platform"]]
                self.assertEqual(got, [want], (sid, want["platform"]))
            if any(r["status"] == "blocked" for r in INDEX["groups"][sid].get("blocked_rows", [])):
                self.assertEqual(summary["groups"][sid]["status"], "blocked", sid)
        a32 = [r for r in rows(summary, "A32") if r["status"] == "blocked"]
        self.assertTrue(any("verified-hello discovery" in r["blocked_on"] for r in a32), a32)
        self.assertNotIn("verified", {r["status"] for r in rows(summary, "A32") if r["platform"].startswith("windows-11 reference wrapper")})

    def test_the_deferred_row_stays_deferred_and_never_counts(self):
        # A synthetic deferred row: the case index carries none since W9's PC run (job 56) proved
        # task 5's Windows endpoint login.
        index = without_index_rows(reduced_index())
        index["groups"]["A32"].setdefault("blocked_rows", []).append({
            "platform": "windows-11 synthetic deferred row",
            "status": "deferred_with_decision",
            "decision": "synthetic: deferred by ruling; the isolated set uses IdentityAgent=none",
        })
        s = Scratch(self, index=index)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        deferred = [r for r in rows(summary, "A32") if r["status"] == "deferred_with_decision"]
        self.assertEqual(len(deferred), 1, rows(summary, "A32"))
        self.assertIn("IdentityAgent=none", deferred[0]["decision"])
        # Every other A32 row verified: the case is verified and the deferred row is unchanged.
        self.assertEqual(summary["groups"]["A32"]["status"], "verified")

    def test_a30_is_blocked_on_b14_and_b7_without_an_a30_group(self):
        self.assertNotIn(A30, INDEX["groups"], "this test pins the case index without an A30 group")
        s = Scratch(self)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        g = summary["groups"][A30]
        self.assertEqual(g["status"], "blocked")
        self.assertEqual([r["status"] for r in g["rows"]], ["blocked"])
        self.assertIn("B14", g["rows"][0]["blocked_on"])
        self.assertIn("B7", g["rows"][0]["blocked_on"])

    def test_the_written_records_validate_and_land_only_where_runs_json_points(self):
        index, inv = completed(reduced_index(), INV)
        s = Scratch(self, index=index, inv=inv)
        rc, summary, err = s.run("--write")
        self.assertEqual(rc, 0, err)
        recs = s.records()
        self.assertEqual(set(recs), set(RUNS["records"]))
        self.assertEqual(s.written(), sorted(Path(r["path"]).name for r in RUNS["records"].values()))
        for sid, rec in recs.items():
            self.assertEqual(ev.validate_record(rec), [], sid)
            self.assertNotIn("secret-thing", json.dumps(rec), sid)
        self.assertEqual(recs["CLI-standalone"]["status"], "verified")
        self.assertEqual(recs["A32"]["status"], "blocked")
        self.assertIn("verified-hello discovery", recs["A32"]["blocked_on"])
        # W9d removed TUI-standalone's blocked connect-step row: with every test passing it verifies.
        self.assertEqual(recs["TUI-standalone"]["status"], "verified")
        self.assertEqual(recs[A30]["status"], "blocked")
        self.assertEqual(recs[A30]["blocked_on"], A30_REASON)


class FailuresAndGaps(unittest.TestCase):
    def test_a_missing_required_test_leaves_its_platform_row_in_progress_never_verified_or_blocked(self):
        index = reduced_index()
        logs = passing_logs(index, INV)
        target, name = a_test(index, "CLI-standalone", "linux")
        del logs["linux"][target][name]
        s = Scratch(self, index=index, logs=logs)
        rc, summary, err = s.run()
        r = row(summary, "CLI-standalone", "linux")
        self.assertEqual(r["status"], "in_progress")
        self.assertIn(f"{target}::{name}", r["incomplete_run"])
        self.assertNotIn("blocked_on", r)
        self.assertEqual(row(summary, "CLI-standalone", "macos")["status"], "verified")
        self.assertEqual(summary["groups"]["CLI-standalone"]["status"], "in_progress")

    def test_a_missing_platform_required_test_leaves_the_windows_row_in_progress(self):
        index = reduced_index()
        logs = passing_logs(index, INV)
        req = INDEX["groups"]["CLI-standalone"]["platform_required"]["windows"]
        target = next(iter(req))
        del logs["windows"][target][req[target][0]]
        s = Scratch(self, index=index, logs=logs)
        rc, summary, err = s.run()
        self.assertEqual(row(summary, "CLI-standalone", "macos")["status"], "verified")
        r = row(summary, "CLI-standalone", "windows")
        self.assertEqual(r["status"], "in_progress")
        self.assertEqual(r["platform_required_not_passed"], {f"{target}::{req[target][0]}": "absent"})

    def test_a_failed_test_keeps_its_platform_row_in_progress(self):
        index = reduced_index()
        logs = passing_logs(index, INV)
        target, name = a_test(index, "A20", "macos")
        logs["macos"][target][name] = "FAILED"
        s = Scratch(self, index=index, logs=logs)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        r = row(summary, "A20", "macos")
        self.assertEqual(r["status"], "in_progress")
        self.assertIn(f"{target}::{name}", r["failed"])
        self.assertEqual(row(summary, "A20", "linux")["status"], "verified")

    def test_a_nonzero_required_command_leaves_no_verified_row_on_that_platform(self):
        s = Scratch(self, commands={"linux": "exit 0: build\nexit 101: cargo test (synthetic)\n"})
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        for sid in GROUPS:
            if "linux" not in declared(s.index, sid):
                continue
            r = row(summary, sid, "linux")
            self.assertEqual(r["status"], "in_progress", sid)
            self.assertIn("cargo test (synthetic)", r["failed_commands"], sid)
            self.assertEqual(row(summary, sid, "macos")["status"], "verified", sid)

    def test_a_platform_that_did_not_run_is_blocked_with_the_exact_missing_platform(self):
        index = reduced_index()
        logs = passing_logs(index, INV)
        logs["windows"] = {}
        reason = "the Windows 11 x64 PC: no native run at this commit (synthetic)"
        s = Scratch(self, index=index, logs=logs, platforms={"windows": {"unavailable": reason}})
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        for sid in GROUPS:
            if "windows" not in declared(index, sid):
                continue
            r = row(summary, sid, "windows")
            self.assertEqual(r["status"], "blocked", sid)
            self.assertEqual(r["blocked_on"], reason, sid)


class IndexRows(unittest.TestCase):
    def test_the_committed_index_rows_are_well_formed(self):
        self.assertEqual(m07.index_row_problems(INDEX), [])

    def bad(self, change):
        index = reduced_index()
        r = index["groups"]["A32"]["blocked_rows"][0]
        self.assertEqual(r["status"], "blocked")
        change(r)
        return index

    def test_an_index_row_claiming_verified_or_in_progress_is_refused_and_nothing_is_written(self):
        for status in ("verified", "in_progress", "implemented_unverified"):
            index = self.bad(lambda r: r.update(status=status))
            s = Scratch(self, index=index)
            rc, summary, err = s.run("--write")
            self.assertEqual(rc, 1, status)
            self.assertIn("never anything a run decides", err, status)
            self.assertEqual(s.written(), [], status)

    def test_an_index_row_without_its_reason_is_refused(self):
        cases = [
            lambda r: r.pop("blocked_on"),
            lambda r: r.update(blocked_on="  "),
            lambda r: r.update(status="deferred_with_decision"),
            lambda r: r.update(status="not_started"),
            lambda r: r.pop("platform"),
        ]
        for change in cases:
            index = self.bad(change)
            self.assertTrue(m07.index_row_problems(index))
            s = Scratch(self, index=index)
            rc, _, err = s.run("--write")
            self.assertEqual(rc, 1, err)
            self.assertEqual(s.written(), [])

    def test_check_inventory_reports_a_bad_index_row(self):
        index = self.bad(lambda r: r.update(status="verified"))
        self.assertTrue(any("never anything a run decides" in p for p in ev.check_index(index)))


class A30NeverPasses(unittest.TestCase):
    def test_an_a30_group_whose_every_test_passed_is_still_blocked_and_its_rows_kept(self):
        index, inv = with_tested_a30(reduced_index(), INV)
        s = Scratch(self, index=index, inv=inv)
        rc, summary, err = s.run("--write")
        self.assertEqual(rc, 0, err)
        g = summary["groups"][A30]
        self.assertEqual(g["status"], "blocked")
        self.assertEqual(row(summary, A30, "linux")["status"], "verified")
        self.assertEqual([r for r in g["rows"] if r["status"] == "blocked"], [m07.owner_row(A30)])
        rec = s.records()[A30]
        self.assertEqual(rec["status"], "blocked")
        self.assertEqual(rec["blocked_on"], A30_REASON)

    def test_the_index_may_carry_the_owner_row_itself_without_it_being_doubled(self):
        index, inv = with_tested_a30(reduced_index(), INV)
        index["groups"][A30]["blocked_rows"] = [m07.owner_row(A30)]
        s = Scratch(self, index=index, inv=inv)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        self.assertEqual(sum(r == m07.owner_row(A30) for r in rows(summary, A30)), 1)

    def test_the_exit_record_is_blocked_on_a30_even_when_every_other_row_is_verified(self):
        index, inv = completed(without_index_rows(reduced_index()), INV)
        index = with_exit_claim(index)
        records = dict(RUNS["records"], **{EXIT_KEY: EXIT_RECORD})
        s = Scratch(self, index=index, inv=inv, records=records)
        rc, summary, err = s.run("--write")
        self.assertEqual(rc, 0, err)
        claim = summary["exit_claims"][EXIT_KEY]
        self.assertEqual(claim["status"], "blocked")
        self.assertEqual([r for r in claim["rows"] if r["status"] != "verified"], [m07.owner_row(A30)])
        recs = s.records()
        self.assertEqual(recs[EXIT_KEY]["status"], "blocked")
        self.assertEqual(recs[EXIT_KEY]["blocked_on"], A30_REASON)
        self.assertEqual(ev.validate_record(recs[EXIT_KEY]), [])
        for sid in GROUPS:
            self.assertEqual(recs[sid]["status"], "verified", sid)

    def test_an_exit_claim_that_lists_a30_carries_its_row_with_or_without_an_a30_group(self):
        plain = with_exit_claim(without_index_rows(reduced_index()), groups=[*GROUPS, A30])
        tested, inv = with_tested_a30(without_index_rows(reduced_index()), INV)
        tested = with_exit_claim(tested, groups=[*GROUPS, A30])
        for index, inventory in ((plain, INV), (tested, inv)):
            s = Scratch(self, index=index, inv=inventory)
            rc, summary, err = s.run()
            self.assertEqual(rc, 0, err)
            claim = summary["exit_claims"][EXIT_KEY]
            self.assertEqual(claim["status"], "blocked")
            self.assertEqual(sum(r == m07.owner_row(A30) for r in claim["rows"]), 1)

    def test_an_exit_claim_that_is_not_the_exit_record_and_omits_a30_is_left_alone(self):
        index, inv = completed(without_index_rows(reduced_index()), INV)
        index = with_exit_claim(index, groups=["CLI-standalone"])
        s = Scratch(self, index=index, inv=inv)
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        self.assertEqual(summary["exit_claims"][EXIT_KEY]["status"], "verified")

    def test_records_refuse_an_a30_or_exit_record_that_is_not_blocked(self):
        cfg = {"records": {A30: dict(RUNS["records"][A30])}, "case_index": "x", "summary_out": "y"}
        summary = {"groups": {A30: {"tests": 0, "rows": [{"platform": "p", "status": "verified"}], "status": "verified"}},
                   "exit_claims": {}}
        with self.assertRaises(ev.RunError):
            ev.records(cfg, summary, {})
        cfg = {"records": {EXIT_KEY: dict(EXIT_RECORD)}, "case_index": "x", "summary_out": "y"}
        summary = {"groups": {}, "exit_claims": {EXIT_KEY: {"tests": 1, "rows": [{"platform": "p", "status": "verified"}],
                                                            "status": "verified", "note": None}}}
        with self.assertRaises(ev.RunError):
            ev.records(cfg, summary, {})

    def test_records_refuse_a_record_with_no_section_or_without_the_m07_prefix(self):
        s = Scratch(self, records=dict(RUNS["records"], **{EXIT_KEY: EXIT_RECORD}))
        rc, _, err = s.run("--write")
        self.assertEqual(rc, 2)
        self.assertIn("no section of the case index", err)
        self.assertEqual(s.written(), [])
        bad = copy.deepcopy(RUNS["records"])
        bad["A20"]["path"] = "tests/evidence/m06-a20.json"
        s = Scratch(self, records=bad)
        rc, _, err = s.run("--write")
        self.assertEqual(rc, 2)
        self.assertIn("does not start with m07-", err)
        self.assertEqual(s.written(), [])


class ObservationsAndFiles(unittest.TestCase):
    def test_m07_observation_lines_reach_the_row_of_the_test_that_printed_them(self):
        index = reduced_index()
        target, name = a_test(index, "CLI-standalone", "macos")
        line = "m07 observation: synthetic step answered in 12 ms"
        s = Scratch(self, index=index, observations={"macos": {(target, name): [line, "not kept"]}})
        rc, summary, err = s.run()
        self.assertEqual(rc, 0, err)
        self.assertEqual(row(summary, "CLI-standalone", "macos")["observations"], {f"{target}::{name}": [line]})

    def test_write_refuses_while_a_target_is_skipped(self):
        env = dict(os.environ, HM_SKIP_TARGETS="e2e_cli_m07", PYTHONDONTWRITEBYTECODE="1")
        r = subprocess.run(
            [sys.executable, "-I", "-B", str(HERE / "m07-evidence.py"), "--config", str(HERE / "runs.json"), "--write"],
            capture_output=True, text=True, env=env, cwd=ROOT,
        )
        self.assertEqual(r.returncode, 2)
        self.assertIn("never written from a reduced case index", r.stderr)

    def test_no_unit_target_is_selected_with_a_feature(self):
        where = ev.cargo_targets(ROOT)
        self.assertEqual(where["heimdall_transport_iroh-unit"][1], ["--lib"])
        self.assertFalse([t for t, (_, sel) in where.items() if t.endswith("-unit") and "--features" in sel])

    def test_the_committed_files_agree_with_one_another(self):
        self.assertEqual(set(RUNS["records"]), set(INDEX["groups"]) | set(INDEX["exit_claims"]) | set(m07.OWNER_BLOCKED))
        self.assertEqual(ev.check_index(INDEX), [])
        self.assertEqual(ev.check_inventory(reduced_index(), INV), [])
        self.assertEqual(reduced_index()["groups"], INDEX["groups"], "the committed inventory resolves every target the index names")
        for sid, rec in RUNS["records"].items():
            self.assertTrue(rec["path"].startswith("tests/evidence/m07-"), sid)
        self.assertEqual(set(RUNS["platforms"]), set(INDEX["platforms"]))
        self.assertEqual(INDEX["build_host"], "macos")
        self.assertEqual(RUNS["build_commit"], None, "runs.json is a template: no native run has happened")
        self.assertEqual(INV["build_host"], "macos")
        self.assertEqual(sorted(INV["scanned_platforms"]), ["linux", "windows"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
