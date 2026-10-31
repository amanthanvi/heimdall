#!/usr/bin/env python3
"""X1d: finish the redacted host harness records and write the two per-candidate summary records.

usage: python3 -I make-records.py <repo-root>

Reads tests/evidence/artifacts/g02-r4/x1d/<label>/ (redacted copies of the host outputs) and
  1. in each host harness record <label>/g02-<c>-conformance-linux-x64-x1d-<label>.json: maps evidence_paths to the
     repository copies and appends the X1d limitation lines (nothing else changes; re-running is idempotent);
  2. writes tests/evidence/g02-<c>-linux-x64-no-toolchain-hosts.json, one row per host in observed_result.per_host
     (tests/evidence/README.md multi-row convention: the top-level status is the lowest row status).
"""
import json
import re
import sys
from datetime import datetime
from pathlib import Path

XD = "tests/evidence/artifacts/g02-r4/x1d"
HOSTS = ("ubuntu2404-kvm", "debian13-x64")
COMMIT = {"go": "84c7665", "rust": "001a791"}
X1C_REC = "tests/evidence/g02-{c}-conformance-linux-x64-x1b.json"
ORDER = ["blocked", "not_started", "in_progress", "implemented_unverified", "verified"]
# expected exits of the no-toolchain and user-check commands (X1c's notoolchain.txt, contract exit codes)
EXPECT = [("version --json", 0), ("profile show homelab", 0), ("profile show spaced", 0),
          ("profile show (spaced copy in this dir)", 0), ("profile show forbidden-key", 2),
          ("run -- /bin/sh -c 'exit 7'", 7), ("agent list", 5)]

HOSTINFO = {
    "ubuntu2404-kvm": {
        "what": "the owner's long-lived Ubuntu 24.04.5 server VM (KVM guest, 4 vCPUs, 8 GB), reached over SSH as "
                "a non-root user; not freshly installed",
        "other_software": "a container runtime running the owner's service; C compiler and make (gcc, cc, make); "
                          "Python 3.12 with venv/ensurepip; Perl; Node.js in the user's ~/.local/bin; tmux; strace; "
                          "a Go module cache (<home>/go/pkg) and Go build cache (<home>/.cache/go-build) left from "
                          "earlier use, with no go executable anywhere searched",
        "venv_method": "python3 -m venv + pip install --require-hashes -r tests/g02/requirements.txt (as X1c)",
        "write_check": "strace -f write-class system call scan (strace installed; bwrap not installed)",
    },
    "debian13-x64": {
        "what": "the owner's long-lived Debian 13 x86_64 server (16 CPUs, 64 GB; systemd-detect-virt: none), reached "
                "over SSH as a non-root user; not freshly installed; busy with the owner's projects during the run",
        "other_software": "many CPU-bound worker processes and headless-browser processes of the owner's projects "
                          "(load average 9 to 32 on 16 CPUs while probed); C compiler and make (gcc, cc, make); "
                          "Python 3.13 without venv/ensurepip and without pip; Perl; bubblewrap; tmux; no Node.js, "
                          "no container runtime on PATH",
        "venv_method": "python3 -m venv failed (exit 1: ensurepip is not available; the python3-venv package is not "
                       "installed and no package may be installed); used python3 -m venv --without-pip plus "
                       "x1d/wheel-install.py: the two wheels pip downloaded on the Mac in hash-checking mode "
                       "(pip download --require-hashes), re-checked on the host against the requirements.txt sha256 "
                       "pins and unpacked into the venv's site-packages",
        "write_check": "bwrap --ro-bind / / (whole file system read-only; bwrap installed, strace not installed)",
    },
}


def load(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def dump(path, rec):
    Path(path).write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def kv(text, key):
    m = re.search(r"^%s=(.*)$" % re.escape(key), text, re.M)
    return m.group(1).strip() if m else None


def section(text, start, end):
    """Lines of text from the first line starting with `start` up to (not including) the next starting with end."""
    out, on = [], False
    for line in text.splitlines():
        if line.startswith(start):
            on = True
        elif on and end and line.startswith(end):
            break
        if on:
            out.append(line)
    return out


def results(lines):
    """[(command label, rc, rest)] for every '<label> rc=<n> ...' line, checked against EXPECT."""
    res, bad = [], []
    for line in lines:
        m = re.match(r"\s*(.+?) rc=(\d+)(.*)$", line)
        if not m:
            continue
        lab, rc = m.group(1), int(m.group(2))
        want = next((w for k, w in EXPECT if lab.startswith(k)), None)
        if lab.startswith("run -- true"):
            want = None   # PATH lookup: 0 with /usr/bin:/bin, 127 with the empty PATH directory (X1c)
        res.append(line.strip())
        if want is not None and rc != want:
            bad.append(line.strip())
        if "canary_prefix_hits=" in line and not line.rstrip().endswith("canary_prefix_hits=0"):
            bad.append(line.strip())
    return res, bad


STRACE_RC = {"cmd1": 0, "cmd2": 0, "cmd3": 2, "cmd4": 7, "cmd5": 5}


def user_checks(lines):
    """(number of contract-coded command results, unexpected lines) for one candidate's user-checks.txt section."""
    res, bad = results(lines)
    coded = sum(1 for x in res if any(x.startswith(k) for k, _ in EXPECT))
    for line in lines:
        t = line.strip()
        m = re.match(r"(cmd\d) \(.*\) rc=(\d+)$", t)
        if m and int(m.group(2)) != STRACE_RC[m.group(1)]:
            bad.append(t)
        m = re.match(r"(control|cmd\d)\.log: \d+ traced calls; write-class: (\d+)$", t)
        if m and ((m.group(1) == "control") != (int(m.group(2)) > 0)):
            bad.append(t)   # the control must show a write, the heimdall-proto commands none
        m = re.match(r"positive control /bin/true rc=(\d+)", t)
        if m and m.group(1) != "0":
            bad.append(t)
        m = re.match(r"write control .* rc=(\d+)", t)
        if m and m.group(1) == "0":
            bad.append(t)
        if "control invalid" in t or "CONTROL FILE EXISTS" in t:
            bad.append(t)
    return coded, bad


def host_row(repo, c, h):
    d = repo / XD / h
    rec = load(d / f"g02-{c}-conformance-linux-x64-x1d-{h}.json")
    orr = rec["observed_result"]
    facts = (d / "hostfacts-start.txt").read_text(encoding="utf-8")
    facts_end = (d / "hostfacts-end.txt").read_text(encoding="utf-8")
    runlog = (d / "run-linux.log").read_text(encoding="utf-8")
    m = re.search(r"^== %s exit (\d+) (\S+) loadavg ([0-9. ]+?) running_tasks" % c, runlog, re.M)
    harness_exit = int(m.group(1)) if m else None
    nt = (d / "notoolchain.txt").read_text(encoding="utf-8")
    nt_lines = section(nt, f"=== {c} ", "=== ")
    nt_res, nt_bad = results(nt_lines)
    uc = (d / "user-checks.txt").read_text(encoding="utf-8")
    uc_lines = section(uc, f"=== {c}", "=== ")
    uc_coded, uc_bad = user_checks(uc_lines)
    uc_want = 20 if h == "debian13-x64" else 15   # sections 2 (x2) and 3, plus bwrap's run of section 5
    tool = {t: re.search(r"^  %s: (.*)$" % t, facts, re.M).group(1) for t in ("go", "gofmt", "rustc", "cargo", "rustup")}
    found = section(facts, "executables named go", "toolchain directories")[1:]
    toolchain_ok = all(v == "absent" for v in tool.values()) and found == ["  (end of list)"]
    failed_ng = sorted({a["desc"] for ch in orr["checks"] for a in ch.get("assertions", []) if not a.get("ok", True)})
    nt_ok = not nt_bad and len(nt_res) == 14
    uc_ok = not uc_bad and uc_coded == uc_want
    complete = rec["status"] == "verified" and harness_exit is not None and len(nt_res) == 14 and uc_coded == uc_want
    status = "verified" if complete else "in_progress"
    verdict = "pass" if (orr["verdict"] == "pass" and harness_exit == 0 and nt_ok and uc_ok and toolchain_ok) else (
        "fail" if orr["verdict"] == "fail" or nt_bad or uc_bad else "inconclusive")
    row = {
        "status": status,
        "verdict": verdict,
        "host": HOSTINFO[h]["what"],
        "harness": {"record": f"{XD}/{h}/g02-{c}-conformance-linux-x64-x1d-{h}.json", "exit_code": harness_exit,
                    "status": rec["status"], "verdict": orr["verdict"], "summary": orr["summary"],
                    "console": f"{XD}/{h}/console-{c}.log", "artifacts": f"{XD}/{h}/arts-{c}",
                    "non_gating_failed_assertions": failed_ng},
        "toolchain_absent": {"command_v_non_interactive": tool,
                             "command_v_login_shell": dict(re.findall(
                                 r"^  (go|gofmt|rustc|cargo|rustup): (.*)$",
                                 "\n".join(section(facts, "toolchain commands, command -v in a login",
                                                   "executables named")), re.M)),
                             "executables_found_by_find": found[:-1],
                             "all_absent": toolchain_ok,
                             "source": f"{XD}/{h}/hostfacts-start.txt"},
        "no_toolchain_commands": {"source": f"{XD}/{h}/notoolchain.txt", "results": nt_res,
                                  "unexpected": nt_bad, "as_x1c": nt_ok},
        "user_checks": {"source": f"{XD}/{h}/user-checks.txt", "write_check": HOSTINFO[h]["write_check"],
                        "results": [x.strip() for x in uc_lines if x.strip()],
                        "contract_coded_results": uc_coded, "unexpected": uc_bad, "all_expected": uc_ok},
        "comparison_with_x1c": f"{XD}/compare.txt (section '{h} vs X1c') and {XD}/README.md",
        "loadavg": {"facts_start": kv(facts, "loadavg"), "harness_start": rec["environment"]["loadavg_start"],
                    "harness_end": rec["environment"]["loadavg_end"], "facts_end": kv(facts_end, "loadavg")},
    }
    env = {"label": h, "what": HOSTINFO[h]["what"], "os": kv(facts, "os"), "kernel": kv(facts, "kernel").split(" machine=")[0],
           "machine": kv(facts, "kernel").split(" machine=")[1],
           "glibc": kv(facts, "glibc"), "virtualisation": kv(facts, "virt"), "cpu_count": rec["environment"]["cpu_count"],
           "memtotal_kb": int(kv(facts, "nproc").split("memtotal_kb=")[1].split()[0]),
           "python": rec["environment"]["python"], "bash": kv(facts, "bash"), "zsh": kv(facts, "zsh"),
           "openssh": kv(facts, "openssh"), "locale": "LANG=" + kv(facts, "LANG").replace(" LC_ALL=", ", LC_ALL="), "non_root": kv(facts, "uid_is_root") == "no",
           "venv_method": HOSTINFO[h]["venv_method"], "other_software": HOSTINFO[h]["other_software"],
           "harness_nice": 10}
    prov = [dict(x, host=h) for x in rec["provider_versions"]]
    return rec, row, env, prov


def finish_host_record(repo, c, h):
    path = repo / XD / h / f"g02-{c}-conformance-linux-x64-x1d-{h}.json"
    rec = load(path)
    rec["evidence_paths"] = [f"{XD}/{h}/g02-{c}-conformance-linux-x64-x1d-{h}.json", f"{XD}/{h}/arts-{c}",
                             f"{XD}/{h}/console-{c}.log", f"{XD}/README.md",
                             f"tests/evidence/g02-{c}-linux-x64-no-toolchain-hosts.json"]
    tag = "Added by X1d (task M00-T05-r5-x1d-linux-hosts)"
    rec["limitations"] = [x for x in rec["limitations"] if not x.startswith(tag)] + [
        f"{tag} after the harness wrote this record: the home directory rewritten to <home> (the user and host "
        "names to <user> and <host> wherever they occurred), evidence_paths mapped to the repository copies, and these "
        "limitation lines appended. Nothing else was changed.",
        f"{tag}: artifact prototypes/{c}/dist/linux-x64/heimdall-proto, the post-fix (X1b) build also run by X1c "
        f"(same sha256); not rebuilt. build_commit is the harness archive commit (51413ebb); the harness files are "
        f"identical to X1c's cfd97d23 and X1's 772a6b1 (git diff empty). Candidate commit {COMMIT[c]}.",
        f"{tag}: native run on {HOSTINFO[h]['what']}, without a Go or Rust toolchain (command -v and a file "
        "search, hostfacts-start.txt), harness under nice -n 10. The harness's generic K13 text above about Docker "
        "Desktop's arm64 VM does not describe this run; linux-x64 is not a K13 verdict platform.",
        f"{tag}: harness venv: {HOSTINFO[h]['venv_method']}.",
        f"{tag}: zsh is not installed on this host, so the zsh K6e forms (non-gating) were not run; bash gated K6e.",
        f"{tag}: summary over both hosts and the extra user checks: tests/evidence/g02-{c}-linux-x64-no-toolchain-hosts.json.",
        f"{tag}: no independent review of this run.",
    ]
    dump(path, rec)


def main():
    repo = Path(sys.argv[1])
    for c in ("go", "rust"):
        for h in HOSTS:
            finish_host_record(repo, c, h)
        rows, envs, provs, recs = {}, {}, [], {}
        for h in HOSTS:
            rec, row, env, prov = host_row(repo, c, h)
            rows[h], envs[h], recs[h] = row, env, rec
            provs += prov
        status = min((r["status"] for r in rows.values()), key=ORDER.index)
        vds = {r["verdict"] for r in rows.values()}
        verdict = "pass" if vds == {"pass"} else ("fail" if "fail" in vds else "inconclusive")
        digest = {recs[h]["artifact_digest"] for h in HOSTS}
        assert len(digest) == 1, digest
        out = {
            "case_id": f"G02-{c}-linux-x64-no-toolchain-hosts",
            "status": status,
            "requirement_ids": recs[HOSTS[0]]["requirement_ids"],
            "build_commit": "51413ebb",
            "artifact_digest": digest.pop(),
            "environment": {
                "subject": "artifact", "platform": "linux-x64", "candidate": c, "candidate_commit": COMMIT[c],
                "artifact_dir": f"prototypes/{c}/dist/linux-x64", "harness_version": recs[HOSTS[0]]["environment"]["harness_version"],
                "plan_wording": "plan.md section 3 G02: test release artifacts on clean Windows, macOS, and Linux "
                                "machines without the candidate's development toolchain",
                "hosts": envs,
            },
            "provider_versions": provs,
            "started_at": min((recs[h]["started_at"] for h in HOSTS), key=datetime.fromisoformat),
            "commands_or_harness": [
                f"{XD}/setup.sh (venv; per host method in environment.hosts.<label>.venv_method)",
                f"nice -n 10 tests/g02/.venv/bin/python tests/g02/conformance.py --bin <home>/hm-m00/M00-T05-r5-x1d/art/{c}/heimdall-proto "
                f"--candidate {c} --case-id G02-{c}-conformance-linux-x64-x1d-<label> --build-commit 51413ebb ... "
                f"(via {XD}/run-linux.sh <label>; full command line in each host record)",
                f"{XD}/notoolchain.sh (X1c's commands under env -i, PATH=/usr/bin:/bin and an empty PATH directory)",
                f"{XD}/user-checks.sh (one file; spaced/non-ASCII location; read-only HOME, TMPDIR and working "
                "directory; strace write scan or bwrap read-only root)",
                f"{XD}/hostfacts.sh (OS, kernel, glibc, CPUs, load, shells, toolchain absence)",
                f"{XD}/compare.py (comparison with X1c)",
            ],
            "observed_result": {
                "verdict": verdict,
                "criterion": "per host: (a) no go, gofmt, rustc, cargo or rustup found (command -v in a non-interactive "
                             "and a login shell, file search of /usr/local, /opt, /usr/lib and the home directory); "
                             "(b) the full harness 2.4.2 catalogue passes natively (exit 0, every check pass); (c) the "
                             "X1c no-toolchain commands give X1c's exit codes under env -i with PATH=/usr/bin:/bin and "
                             "with an empty PATH directory, with no canary prefix; (d) the single-file artifact, copied "
                             "alone into a directory with spaces and non-ASCII characters, gives the same exit codes "
                             "from there, also with HOME, TMPDIR and the working directory read-only, and the write "
                             "check (strace scan or bwrap read-only root) shows no write outside those directories",
                "per_host": rows,
                "not_covered": ["freshly installed machines (both hosts are long-lived and carry other software, "
                                "including a C compiler)", "Linux distributions and kernels other than these two",
                                "musl-based distributions", "zsh K6e forms (zsh not installed)",
                                "windows-x64 and darwin (separate records)"],
            },
            "evidence_paths": [f"tests/evidence/g02-{c}-linux-x64-no-toolchain-hosts.json", f"{XD}/README.md",
                               f"{XD}/compare.txt", f"{XD}/commands.txt", f"{XD}/inputs.sha256"]
                              + [f"{XD}/{h}" for h in HOSTS],
            "limitations": [
                "Not clean machines in the plan's sense: both are the owner's long-lived hosts, not fresh installs. "
                "Neither has a Go or Rust toolchain, but both have other software (environment.hosts.<label>."
                "other_software), including a C compiler. A static artifact does not use it; the check that it is not "
                "needed is that the binaries are static (file, ldd) and run under env -i with an empty PATH directory.",
                "debian13-x64 was busy with the owner's workloads (load averages in per_host.debian13-x64.loadavg; the "
                "harness adds its own 'machine load was high' limitation when the load exceeds 0.75 x CPUs). Timing "
                "observations there are not comparable with an idle host. The harness ran under nice -n 10 on both hosts.",
                "The harness venv on debian13-x64 was not created by pip (environment.hosts.debian13-x64.venv_method). "
                "pip's own install step was replaced by hash-checked extraction of the same two pinned wheels.",
                "One run per candidate per host; timing observations are single samples.",
                "Artifact provenance as in X1c: the X1b fix round's bytes, equal to the reviewers' rebuilds; a build of "
                "the committed candidate trees was not re-checked (no rebuild in this task).",
                "linux-x64 is not a K13 verdict platform; these records are G02 practical-distribution evidence.",
                "No independent review of this run.",
            ],
        }
        if status == "blocked":
            out["blocked_on"] = "see per_host"
        dump(repo / f"tests/evidence/g02-{c}-linux-x64-no-toolchain-hosts.json", out)
        print(f"{c}: status {status}, verdict {verdict}; rows " +
              ", ".join(f"{h}={rows[h]['status']}/{rows[h]['verdict']}" for h in HOSTS))


if __name__ == "__main__":
    main()
