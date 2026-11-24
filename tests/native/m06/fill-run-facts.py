#!/usr/bin/env python3
"""M06 exit (RESEARCH §0 item 6, §1 step 0): fill an exit run configuration's identity fields
from real inputs, never by hand: build_commit, started_at, environment, every platform's
artifact_digest and the run's artifact_digest, with <artifacts_root>/digests.txt.

Inputs, each read here:
  * build_commit: `git rev-parse HEAD` of this checkout, which must be clean (`git status
    --porcelain` empty) and, with --commit, exactly that commit. A platform output that names
    its commit (the Windows bundle's `build-commit` host fact, the controller recorder's
    `commit=` in build.txt) must name that platform's run commit (below; default HEAD);
  * ⟨M06 exit C10b⟩ a platform's optional `run_commit` (40 hex, exit configuration only, not the
    record schema): the commit that platform's run was built from, when it is not HEAD. Refused
    unless it is an ancestor of HEAD (`git merge-base --is-ancestor`); when it differs from HEAD,
    `run_commit_reason` (non-empty text) is required, and the product drift
    `git diff --name-only <run_commit> HEAD -- crates ':!crates/testkit'` is computed and written
    beside the reason as `run_commit_drift` ({range, count, files}). Every drifted file must be
    listed in the optional `run_commit_drift_allow` (the files the reason names), and every listed
    file must have drifted: anything else is refused. The reason and the drift are appended to the
    platform's label, "<label>; ran at <short> (<reason>; product drift <n> files <range>)", so they
    reach the records through the label field. A platform whose outputs name no commit may still
    give run_commit: the ancestor, reason and drift rules apply all the same;
  * the binaries' digests: every `<name> sha256: <hex>` line of the build.txt files beside a
    platform's logs (run-linux.sh, run-crosshost.sh, the Windows bundle, the controller
    recorder), and for each --bin PLATFORM:NAME=PATH the sha256 computed here (macOS: check.sh
    builds in this checkout's target/, so its binaries are named on the command line). A
    platform that ran and has no digest is refused;
  * started_at: --started-at, RFC 3339 with an offset (the instant the first exit step started,
    as the integrator noted it); refused when malformed or later than the oldest configured
    artifact file;
  * environment: the build host's `uname -srm`, `rustc --version`, `cargo --version` and
    `zig version`, and each platform's label. Nothing secret, no path, no account name.
digests.txt holds `<platform> <name> sha256: <hex>` lines, sorted; a platform's
artifact_digest is the sha256 of its own lines, and a value the configuration already holds
(the Windows importer's, over the imported files) is kept, never replaced. The run's
artifact_digest is the sha256 of digests.txt. The configuration's evidence_paths gain
digests.txt and the configuration itself. Everything written is scanned first with
import-windows-bundle.py's checks (canaries, SIDs, home paths, non-loopback addresses).

Usage (repository root):
  python3 -I tests/native/m06/fill-run-facts.py --config $A/runs.json --started-at <RFC 3339>
      [--commit <40hex>] [--bin macos:heimdall=target/debug/heimdall ...] [--dry-run]
Exit: 0 written (or, with --dry-run, printed), 1 refused (nothing written), 2 usage.
"""

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")
SHA_LINE = re.compile(r"(?m)^(\S(?:.*\S)?) sha256: ([0-9a-f]{64})$")


class Refused(Exception):
    """Nothing is written."""


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


BUNDLE = load("import_windows_bundle", HERE.parent / "m02" / "import-windows-bundle.py")


def run(*cmd, cwd=ROOT):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as e:
        raise Refused(f"{cmd[0]} failed: {e}") from None


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_started_at(text):
    if not RFC3339.fullmatch(text or ""):
        raise Refused("--started-at must be RFC 3339 with an offset (e.g. 2026-11-23T14:05:00Z)")
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))


def platform_files(base, p, key):
    return [base / rel for rel in p.get(key, [])]


def collect(cfg, base, bins):
    """({platform: [(name, sha256)]}, {platform: commit named by its outputs})."""
    out, commits = {}, {}
    for pname, p in cfg["platforms"].items():
        if p.get("unavailable"):
            continue
        sums = []
        dirs = sorted({f.parent for f in platform_files(base, p, "logs")})
        for d in dirs:
            b = d / "build.txt"
            if b.is_file():
                text = b.read_text(encoding="utf-8", errors="replace")
                prefix = "" if len(dirs) == 1 else f"{d.name}/"
                sums += [(prefix + n, h) for n, h in SHA_LINE.findall(text)]
                for c in re.findall(r"(?m)^commit=([0-9a-f]{40})$", text):
                    commits.setdefault(pname, set()).add(c)
        for f in platform_files(base, p, "facts"):
            if f.is_file():
                for c in re.findall(r"(?m)^build-commit=([0-9a-f]{40})$", f.read_text(encoding="utf-8", errors="replace")):
                    commits.setdefault(pname, set()).add(c)
        for name, path in bins.get(pname, []):
            if not Path(path).is_file():
                raise Refused(f"--bin {pname}:{name}: no such file")
            sums.append((name, sha256_file(path)))
        if not sums:
            raise Refused(f"{pname} ran but no binary digest was found (no build.txt beside its logs, no --bin {pname}:...)")
        out[pname] = sorted(set(sums))
    return out, commits


def oldest_artifact(cfg, base):
    times = []
    for p in cfg["platforms"].values():
        if p.get("unavailable"):
            continue
        for key in ("logs", "commands_logs", "facts"):
            for f in platform_files(base, p, key):
                if f.is_file():
                    times.append(dt.datetime.fromtimestamp(f.stat().st_mtime, dt.timezone.utc))
    return min(times) if times else None


def is_ancestor(commit, head, repo):
    try:
        r = subprocess.run(("git", "merge-base", "--is-ancestor", commit, head), cwd=repo, capture_output=True, text=True)
    except OSError as e:
        raise Refused(f"git failed: {e}") from None
    if r.returncode not in (0, 1):
        raise Refused(f"git merge-base --is-ancestor {commit} {head} failed (exit {r.returncode}): is {commit} a commit of this checkout?")
    return r.returncode == 0


def run_commit_facts(pname, p, head, repo):
    """(the platform's run commit, its drift record or None); raises Refused."""
    rc = p.get("run_commit")
    if rc is None:
        if p.get("run_commit_reason") or p.get("run_commit_drift_allow"):
            raise Refused(f"{pname}: run_commit_reason or run_commit_drift_allow without run_commit")
        return head, None
    if not isinstance(rc, str) or not re.fullmatch(r"[0-9a-f]{40}", rc):
        raise Refused(f"{pname}: run_commit must be 40 lowercase hex digits")
    reason = p.get("run_commit_reason")
    allow = p.get("run_commit_drift_allow") or []
    if not isinstance(allow, list) or not all(isinstance(f, str) and f for f in allow):
        raise Refused(f"{pname}: run_commit_drift_allow must be a list of file paths")
    if not is_ancestor(rc, head, repo):
        raise Refused(f"{pname}: run_commit {rc} is not an ancestor of HEAD {head}")
    if rc == head:
        if allow:
            raise Refused(f"{pname}: run_commit is HEAD, so nothing drifted: run_commit_drift_allow must be empty")
        return rc, None
    if not isinstance(reason, str) or not reason.strip():
        raise Refused(f"{pname}: run_commit {rc} is not HEAD {head} and run_commit_reason is missing or empty")
    out = run("git", "diff", "--name-only", rc, head, "--", "crates", ":!crates/testkit", cwd=repo)
    files = sorted(f for f in (out or "").splitlines() if f)
    extra = sorted(set(files) - set(allow))
    if extra:
        raise Refused(f"{pname}: product files changed in {rc}..{head} and not in run_commit_drift_allow: {', '.join(extra)}")
    stale = sorted(set(allow) - set(files))
    if stale:
        raise Refused(f"{pname}: run_commit_drift_allow names files that did not change in {rc}..{head}: {', '.join(stale)}")
    return rc, {"range": f"{rc}..{head}", "count": len(files), "files": files, "reason": reason.strip()}


def drift_label(label, rc, drift):
    rng = f"{drift['range'].split('..')[0][:8]}..{drift['range'].split('..')[1][:8]}"
    suffix = f"; ran at {rc[:8]} ({drift['reason']}; product drift {drift['count']} files {rng})"
    return label if (label or "").endswith(suffix) else f"{label}{suffix}"


def fill(cfg, cfg_path, started_at, commit=None, bins=None, repo=ROOT):
    """(new configuration, digests.txt text); raises Refused."""
    base = Path(cfg.get("artifacts_root", "."))
    if not base.is_absolute():
        base = ROOT / base
    if run("git", "status", "--porcelain", "--untracked-files=no", cwd=repo):
        raise Refused("the checkout has uncommitted changes to tracked files: the commit would not describe the build")
    head = run("git", "rev-parse", "HEAD", cwd=repo)
    if commit and head != commit:
        raise Refused(f"HEAD is {head}, not --commit {commit}")
    when = parse_started_at(started_at)
    oldest = oldest_artifact(cfg, base)
    if oldest and when > oldest:
        raise Refused(f"--started-at is after the oldest artifact ({oldest.isoformat()})")
    ran_at = {}
    for pname, p in cfg["platforms"].items():
        if not p.get("unavailable"):
            ran_at[pname] = run_commit_facts(pname, p, head, repo)
    sums, commits = collect(cfg, base, bins or {})
    for pname, cs in commits.items():
        want = ran_at[pname][0]
        if cs != {want}:
            what = "HEAD" if want == head else "its run_commit"
            raise Refused(f"{pname}'s outputs name commit {', '.join(sorted(cs))}, not {what} {want}")
    lines = [f"{pname} {name} sha256: {h}" for pname in sorted(sums) for name, h in sums[pname]]
    digests = "\n".join(lines) + "\n"
    new = json.loads(json.dumps(cfg))
    for pname, entries in sums.items():
        p = new["platforms"][pname]
        if not p.get("artifact_digest"):
            own = "\n".join(f"{pname} {n} sha256: {h}" for n, h in entries) + "\n"
            p["artifact_digest"] = hashlib.sha256(own.encode()).hexdigest()
    for pname, (rc, drift) in ran_at.items():
        if drift:
            p = new["platforms"][pname]
            p["run_commit_drift"] = {k: drift[k] for k in ("range", "count", "files")}
            p["label"] = drift_label(p.get("label"), rc, drift)
    new["build_commit"] = head
    new["artifact_digest"] = hashlib.sha256(digests.encode()).hexdigest()
    new["started_at"] = started_at
    env = dict(new.get("environment") or {})
    env["build_host"] = {
        "uname": run("uname", "-srm"),
        "rustc": run("rustc", "--version"),
        "cargo": run("cargo", "--version"),
        "zig": run("zig", "version"),
    }
    env["platforms"] = {pname: p.get("label") for pname, p in new["platforms"].items()}
    new["environment"] = env
    paths = list(new.get("evidence_paths") or [])
    for extra in (base / "digests.txt", Path(cfg_path).resolve()):
        rel = os.path.relpath(extra.resolve() if extra.exists() else extra, ROOT)
        if rel not in paths:
            paths.append(rel)
    new["evidence_paths"] = paths
    for text, what in ((json.dumps(new, ensure_ascii=False), "the configuration"), (digests, "digests.txt")):
        why = BUNDLE.sensitive(text)
        if why:
            raise Refused(f"{what} would carry {why}")
    return new, digests, base


def parse_bins(items):
    out = {}
    for item in items:
        m = re.fullmatch(r"([a-z0-9-]+):([A-Za-z0-9._() -]+)=(.+)", item)
        if not m:
            raise Refused(f"--bin {item!r} is not PLATFORM:NAME=PATH")
        out.setdefault(m.group(1), []).append((m.group(2), m.group(3)))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--config", required=True)
    ap.add_argument("--started-at", required=True)
    ap.add_argument("--commit")
    ap.add_argument("--bin", action="append", default=[], metavar="PLATFORM:NAME=PATH")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    if a.commit and not re.fullmatch(r"[0-9a-f]{40}", a.commit):
        print("--commit must be 40 lowercase hex digits", file=sys.stderr)
        return 2
    cfg_path = Path(a.config)
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        bins = parse_bins(a.bin)
        unknown = sorted(set(bins) - set(cfg.get("platforms", {})))
        if unknown:
            raise Refused(f"--bin names unknown platforms: {', '.join(unknown)}")
        new, digests, base = fill(cfg, a.config, a.started_at, a.commit, bins)
    except Refused as e:
        print(f"refused (nothing written): {e}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as e:
        print(f"failed (nothing written): {e}", file=sys.stderr)
        return 1
    if a.dry_run:
        print(digests, end="")
        print(json.dumps({k: new[k] for k in ("build_commit", "artifact_digest", "started_at", "environment")}, indent=2))
        return 0
    (base / "digests.txt").write_text(digests, encoding="utf-8")
    cfg_path.write_text(json.dumps(new, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {base / 'digests.txt'} ({digests.count(chr(10))} digests) and {cfg_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
