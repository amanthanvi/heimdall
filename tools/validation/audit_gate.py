#!/usr/bin/env python3
"""RustSec audit gate (ADR-0012 section 1 item 4; M06-W0-R01/R04; orchestrator rulings of
2026-11-21). Stdlib only. Run from anywhere:

    python3 -I tools/validation/audit_gate.py              # self-tests, then the real audit
    python3 -I tools/validation/audit_gate.py --self-test  # self-tests only

The real audit runs cargo-audit 0.22.1 over the WHOLE Cargo.lock (every target's packages,
whatever the host), with the checked-in `.cargo/audit.toml` (fetch on, stale databases
refused, no ignores) and an empty scratch CARGO_HOME, so no ambient configuration applies.
Any vulnerability fails unless its ID is in tools/validation/audit-ignore.txt. It fails closed:
a missing or unreadable database, a tool error or an invalid report fails with a direct
diagnostic. A missing (or different) cargo-audit fails with exit 3 unless HM_SKIP_AUDIT=1,
which prints "SKIPPED (not merge evidence)".

Exit: 0 pass; 1 a vulnerability (or a failed self-test); 2 no valid report; 3 tool missing.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
IGNORE_FILE = os.path.join(REPO, "tools", "validation", "audit-ignore.txt")
TOOL_VERSION = "0.22.1"


def load_ignores(path):
    ignored = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                ident, _, reason = line.partition(" ")
                ignored[ident] = reason
    return ignored


def evaluate(stdout, tool_exit, stderr, ignored, out=print):
    """Judge one cargo-audit run. Returns the gate's exit code."""
    try:
        report = json.loads(stdout)
        count = report["database"]["advisory-count"]
        deps = report["lockfile"]["dependency-count"]
        vulns = report["vulnerabilities"]["list"]
    except Exception as e:  # no valid report: fail closed with a direct diagnostic
        tail = " | ".join(l.strip() for l in (stderr or "").strip().splitlines()[-3:])
        out("audit: cargo-audit exited %s without a valid report (%s); stderr: %s"
            % (tool_exit, type(e).__name__, tail or "<empty>"))
        return 2
    if not count:
        out("audit: the advisory database loaded no advisories: fail closed")
        return 2
    out("audit: %d advisories loaded; %d lockfile packages (all targets); %d accepted residuals listed"
        % (count, deps, len(ignored)))
    fatal, seen = 0, set()
    for v in vulns:
        ident = v["advisory"]["id"]
        pkg = "%s %s" % (v["package"]["name"], v["package"]["version"])
        if ident in ignored:
            seen.add(ident)
            out("audit: ACCEPTED %s %s: %s" % (ident, pkg, v["advisory"].get("title", "")))
        else:
            fatal += 1
            out("audit: VULNERABILITY %s %s: %s" % (ident, pkg, v["advisory"].get("title", "")))
    for ident in sorted(set(ignored) - seen):
        out("audit: note: accepted residual %s no longer matches the lockfile" % ident)
    for kind, items in sorted(report.get("warnings", {}).items()):
        for w in items:
            adv = w.get("advisory") or {}
            out("audit: warning %s %s %s %s" % (kind, adv.get("id", "-"), w["package"]["name"], w["package"]["version"]))
    return 1 if fatal else 0


def locate_tool(candidates, env, out=print):
    """The cargo-audit command to run, or an exit code (3 missing; 0 explicitly skipped)."""
    for cmd in candidates:
        try:
            r = subprocess.run(cmd + ["--version"], capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if r.returncode == 0 and TOOL_VERSION in r.stdout:
            return cmd
    out("audit: missing prerequisite: cargo-audit %s "
        "(cargo install --locked cargo-audit@%s --root target/tools)" % (TOOL_VERSION, TOOL_VERSION))
    if env.get("HM_SKIP_AUDIT") == "1":
        out("audit: SKIPPED (not merge evidence) by HM_SKIP_AUDIT=1")
        return 0
    return 3


def run_audit():
    local = os.path.join(REPO, "target", "tools", "bin", "cargo-audit")
    tool = locate_tool([[local, "audit"], ["cargo", "audit"]], os.environ)
    if isinstance(tool, int):
        return tool
    scratch_home = tempfile.mkdtemp(prefix="hm-audit-cargo-home-")
    try:
        env = dict(os.environ, CARGO_HOME=scratch_home)
        r = subprocess.run(
            tool + ["--db", os.path.join(REPO, "target", "tools", "advisory-db"),
                    "--file", os.path.join(REPO, "Cargo.lock"), "--json"],
            cwd=REPO, env=env, capture_output=True, text=True, timeout=600)
    finally:
        shutil.rmtree(scratch_home)
    return evaluate(r.stdout, r.returncode, r.stderr, load_ignores(IGNORE_FILE))


def _report(*vulns):
    return json.dumps({
        "database": {"advisory-count": 1555},
        "lockfile": {"dependency-count": 551},
        "vulnerabilities": {"found": bool(vulns), "count": len(vulns), "list": [
            {"advisory": {"id": i, "title": "synthetic"}, "package": {"name": n, "version": v}}
            for i, n, v in vulns]},
        "warnings": {},
    })


def self_test():
    quiet = lambda *_: None
    ignored = {"RUSTSEC-2023-0071": "accepted"}
    cases = [
        # A Windows-only package of the iroh tree, absent from the macOS host tree.
        ("audit_gate_non_host_only_advisory_fails",
         evaluate(_report(("RUSTSEC-9999-0001", "ipconfig", "0.3.4")), 1, "", ignored, quiet) == 1),
        ("audit_gate_host_tree_advisory_fails",
         evaluate(_report(("RUSTSEC-9999-0002", "tokio", "1.54.1")), 1, "", ignored, quiet) == 1),
        ("audit_gate_ignored_id_passes",
         evaluate(_report(("RUSTSEC-2023-0071", "rsa", "0.9.10")), 1, "", ignored, quiet) == 0),
        ("audit_gate_empty_output_fails",
         evaluate("", 1, "error loading advisory database", ignored, quiet) == 2),
        ("audit_gate_zero_advisories_fails",
         evaluate(json.dumps({"database": {"advisory-count": 0}, "lockfile": {"dependency-count": 1},
                              "vulnerabilities": {"list": []}}), 0, "", ignored, quiet) == 2),
        ("audit_gate_missing_tool_fails",
         locate_tool([["/nonexistent/hm-cargo-audit", "audit"]], {}, quiet) == 3),
        ("audit_gate_missing_tool_skip_is_explicit",
         locate_tool([["/nonexistent/hm-cargo-audit", "audit"]], {"HM_SKIP_AUDIT": "1"}, quiet) == 0),
        ("audit_gate_ignore_file_lists_exactly_the_accepted_residuals",
         sorted(load_ignores(IGNORE_FILE)) == ["RUSTSEC-2023-0071", "RUSTSEC-2026-0387"]),
    ]
    failed = 0
    for name, ok in cases:
        print("self-test %s: %s" % (name, "PASS" if ok else "FAIL"))
        failed += not ok
    return 1 if failed else 0


def main(argv):
    rc = self_test()
    if rc or "--self-test" in argv:
        return rc
    return run_audit()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
