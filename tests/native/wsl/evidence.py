#!/usr/bin/env python3
"""Evidence helpers for the G03 WSL harness (stdlib only).

  evidence.py obs-set FILE KEY (--json VALUE | --str VALUE | --file PATH)
      Set KEY in the JSON object stored in FILE (created if missing).
  evidence.py redact-tree DIR
      Redact user/host names (and home-directory prefixes) in every text file under DIR, in place.
  evidence.py record --out FILE --case-id ID [--req R-.. ...]
      [--status blocked --blocked-on TEXT] | [--obs FILE --criteria FILE]
      [--env FILE] [--provider NAME=VERSION]... [--command TEXT]...
      [--evidence PATH]... [--limitation TEXT]... [--build-commit SHA]
      [--started-at RFC3339] [--repo-root DIR]

Status convention when --criteria is given (gate-probe convention in
tests/evidence/README.md, orchestrator decision 2026-10-03): status describes
the evidence, verdict the criterion. Any null criterion (unobservable, failed
control, environment problem) or no criteria -> in_progress, verdict
"inconclusive"; otherwise any false -> verified, verdict "fail"; all true ->
verified, verdict "pass". failed_criteria/unobserved_criteria list the keys.
Harness self-test records are written with no --req (they name no product
requirement). The record matches tests/evidence/record.schema.json.
Identifying values (user, host names) are redacted before writing.
"""
import argparse
import getpass
import json
import os
import re
import socket
import sys

STATUSES = {"not_started", "in_progress", "blocked", "implemented_unverified", "verified", "deferred_with_decision"}
REQ_RE = re.compile(r"^R-[A-Z]{2}-0[1-8]$")


def load(path, default):
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return default


def redactions():
    vals = set()
    for v in (os.environ.get("USER"), os.environ.get("LOGNAME"), os.environ.get("HEIMDALL_G03_WIN_USER")):
        if v and len(v) >= 3:
            vals.add(v)
    try:
        vals.add(getpass.getuser())
    except Exception:  # noqa: BLE001
        pass
    try:
        h = socket.gethostname()
        if h and len(h) >= 3:
            vals.add(h)
    except OSError:
        pass
    return sorted((v for v in vals if v and len(v) >= 3), key=len, reverse=True)


def redact(text):
    for v in redactions():
        # whole-token, case-insensitive (a host named "Mac" must not rewrite "macos")
        text = re.sub(r"(?<![A-Za-z0-9])" + re.escape(v) + r"(?![A-Za-z0-9])", "<redacted>", text, flags=re.IGNORECASE)
    return re.sub(r"S-1-5-21-\d+-\d+-\d+", "S-1-5-21-<redacted>", text)


def cmd_redact_tree(a):
    home = os.path.expanduser("~")
    changed = 0
    for root, _dirs, files in os.walk(a.dir):
        for name in files:
            path = os.path.join(root, name)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    text = fh.read()
            except (UnicodeDecodeError, OSError):
                continue  # binary payloads (e.g. round-trip data) are left untouched
            new = text.replace(home, "<home>") if home and home != "/" else text
            new = redact(new)
            if new != text:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(new)
                changed += 1
    print("redacted files: %d" % changed)
    return 0


def cmd_obs_set(a):
    obj = load(a.file, {})
    if a.json is not None:
        val = json.loads(a.json)
    elif a.from_file is not None:
        with open(a.from_file, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        try:
            val = json.loads(raw)
        except ValueError:
            val = raw
    else:
        val = a.str
    obj[a.key] = val
    with open(a.file, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, sort_keys=True)
    return 0


def cmd_record(a):
    a.req = a.req or []
    for r in a.req:
        if not REQ_RE.match(r):
            sys.exit("bad requirement id %s" % r)
    observed = load(a.obs, None)
    status = a.status
    if a.criteria:
        crit = load(a.criteria, {})
        if observed is None:
            observed = {}
        observed["criteria"] = crit
        failed = sorted(k for k, v in crit.items() if v is False)
        unobserved = sorted(k for k, v in crit.items() if v is None)
        observed["failed_criteria"], observed["unobserved_criteria"] = failed, unobserved
        if unobserved or not crit:
            observed["verdict"], status = "inconclusive", "in_progress"
        elif failed:
            observed["verdict"], status = "fail", "verified"
        else:
            observed["verdict"], status = "pass", "verified"
    if status not in STATUSES:
        sys.exit("bad status %s" % status)
    if status == "blocked":
        if not a.blocked_on:
            sys.exit("blocked requires --blocked-on")
        observed = None
    root = os.path.abspath(a.repo_root) if a.repo_root else None
    paths = []
    for p in a.evidence or []:
        ap = os.path.abspath(p)
        paths.append(os.path.relpath(ap, root) if root and ap.startswith(root + os.sep) else p)
    rec = {
        "case_id": a.case_id,
        "status": status,
        "requirement_ids": a.req,
        "build_commit": a.build_commit,
        "artifact_digest": None,
        "environment": load(a.env, None),
        "provider_versions": [dict(zip(("name", "version"), pv.split("=", 1))) for pv in (a.provider or [])],
        "started_at": a.started_at,
        "commands_or_harness": a.command or None,
        "observed_result": observed,
        "evidence_paths": paths,
        "limitations": a.limitation or [],
        "blocked_on": a.blocked_on if status == "blocked" else None,
    }
    text = redact(json.dumps(rec, indent=2, ensure_ascii=False))
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write(text + "\n")
    print("%s %s" % (a.case_id, status))
    return 0


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("obs-set")
    o.add_argument("file")
    o.add_argument("key")
    g = o.add_mutually_exclusive_group(required=True)
    g.add_argument("--json")
    g.add_argument("--str")
    g.add_argument("--file", dest="from_file")
    t = sub.add_parser("redact-tree")
    t.add_argument("dir")
    r = sub.add_parser("record")
    r.add_argument("--out", required=True)
    r.add_argument("--case-id", required=True)
    r.add_argument("--req", action="append", default=[])
    r.add_argument("--status", default="in_progress")
    r.add_argument("--blocked-on")
    r.add_argument("--obs")
    r.add_argument("--criteria")
    r.add_argument("--env")
    r.add_argument("--provider", action="append")
    r.add_argument("--command", action="append")
    r.add_argument("--evidence", action="append")
    r.add_argument("--limitation", action="append")
    r.add_argument("--build-commit")
    r.add_argument("--started-at")
    r.add_argument("--repo-root")
    a = p.parse_args()
    if a.cmd == "redact-tree":
        return cmd_redact_tree(a)
    return cmd_obs_set(a) if a.cmd == "obs-set" else cmd_record(a)


if __name__ == "__main__":
    sys.exit(main())
