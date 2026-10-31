#!/usr/bin/env python3
"""X1c: turn the redacted harness records into repository records, and point the round-3 records at them.

usage: python3 -I make-records.py <repo-root> <redacted-out-dir>

<redacted-out-dir> holds g02-<c>-conformance-linux-x64-x1b.json as written by tests/g02/conformance.py on the
host, after redact.py. For each candidate this script
  1. maps evidence_paths to the repository copies and appends the X1c limitation lines (nothing else changes);
  2. writes tests/evidence/g02-<c>-conformance-linux-x64-x1b.json (indent 2, ensure_ascii False, like X1);
  3. appends one limitation line to tests/evidence/g02-<c>-conformance-linux-x64.json (round-3 artifact record);
     that file round-trips byte-identically through json.loads/json.dumps(indent=2, ensure_ascii=False).
Re-running it rewrites the x1b records and leaves a round-3 record that already has the identical line unchanged.
"""
import json
import sys
from pathlib import Path

X1C = "tests/evidence/artifacts/g02-r4/x1c"
COMMIT = {"go": "84c7665", "rust": "001a791"}
OLD_DIGEST = {"go": "429063bf6704", "rust": "961e3fb9f02e"}
OLD_COMMIT = {"go": "38b6b72", "rust": "d8f0cbe"}


def dump(path, rec):
    path.write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main():
    repo, out = Path(sys.argv[1]), Path(sys.argv[2])
    for c in ("go", "rust"):
        rec = json.loads((out / f"g02-{c}-conformance-linux-x64-x1b.json").read_text(encoding="utf-8"))
        nh = rec["environment"]["native_host"]
        rec["evidence_paths"] = [
            f"tests/evidence/g02-{c}-conformance-linux-x64-x1b.json",
            f"{X1C}/arts-{c}",
            f"{X1C}/console-{c}.log",
            f"{X1C}/README.md",
        ]
        rec["limitations"] += [
            "Added by X1c (task M00-T05-r5-x1c-linux-x64) after the harness wrote this record: the WSL scratch "
            "directory rewritten to <wslscratch> and the home directory to <wslhome>, evidence_paths mapped to the "
            "repository copies, and these limitation lines appended. Nothing else was changed.",
            f"Artifact: prototypes/{c}/dist/linux-x64/heimdall-proto, the post-fix (X1b) build. Its sha256 "
            f"(artifact_digest) equals prototypes/{c}/dist/manifest.json and the independent reviewer's rebuild "
            f"manifest in tests/evidence/artifacts/g02-r4/x1b/review-{c}/build/; it was not rebuilt here. The fix "
            f"round built it from its working tree on e0ead9b, and the fix was committed as {COMMIT[c]} "
            f"(environment.candidate_commit); that the committed tree reproduces these bytes was not re-checked here. "
            f"build_commit records the harness archive commit (cfd97d23), as X1 recorded 772a6b1; the harness files "
            f"are identical between the two commits (git diff empty).",
            f"Environment: native linux-x64 run in WSL2 {nh['distro']} (kernel {nh['kernel']}, WSL "
            f"{nh['wsl_version']}, x86_64, no container, no emulation) on the owner's Windows 11 PC, as a non-root "
            "user, harness 2.4.2 (environment.native_host). The harness's generic K13 text above about Docker "
            "Desktop's arm64 VM does not describe this run. linux-x64 is not a K13 verdict platform (darwin-arm64 and "
            "linux-arm64 are); this record is X1c cross-platform evidence for the post-fix artifact. The Windows build "
            "was not queried (X1c did not touch Windows).",
            f"Same host as the round-3 linux-x64 record (tests/evidence/g02-{c}-conformance-linux-x64.json, artifact "
            f"{OLD_DIGEST[c]}..., candidate {OLD_COMMIT[c]}), but the WSL kernel changed from "
            "6.18.40.1-microsoft-standard-WSL2 to the one above and OpenSSH from 9.6p1 Ubuntu-3ubuntu13.19 to the "
            "version in provider_versions; a difference between the two records may come from the artifact or from "
            "these host updates. The comparison is in " + X1C + "/compare.txt and README.md.",
            "zsh is not installed on this host (no package installs allowed), so the zsh K6e forms were not run "
            "(observations k6e_job_control zsh-*, k6e_child_self_stop zsh-*: not_run); they are non-gating. bash "
            "5.2.21 gated K6e.",
            "Not a container: unlike tests/g02/linux/run.sh there was no --network none, cap drop or memory limit; the "
            "host also runs the owner's other WSL processes (load average recorded in environment). The harness "
            "binary-under-test environment is unchanged.",
            "No independent review of this run.",
        ]
        dump(repo / f"tests/evidence/g02-{c}-conformance-linux-x64-x1b.json", rec)

        old_path = repo / f"tests/evidence/g02-{c}-conformance-linux-x64.json"
        text = old_path.read_text(encoding="utf-8")
        old = json.loads(text)
        if json.dumps(old, indent=2, ensure_ascii=False) + "\n" != text:
            sys.exit(f"{old_path} does not round-trip; not editing it")
        line = (f"X1c (2026-10-31): the post-fix (X1b) artifact, {COMMIT[c]}, ran on native linux-x64 in "
                f"tests/evidence/g02-{c}-conformance-linux-x64-x1b.json; this record covers only the round-3 "
                f"artifact {OLD_COMMIT[c]}.")
        have = [x for x in old["limitations"] if x.startswith("X1c (")]
        if have == [line]:
            print(f"{c}: wrote the x1b record; {old_path.name} already has the X1c line (unchanged)")
            continue
        if have:
            sys.exit(f"{old_path} has a different X1c line; not editing it")
        old["limitations"].append(line)
        dump(old_path, old)
        print(f"{c}: wrote the x1b record; appended 1 limitation line to {old_path.name}")


if __name__ == "__main__":
    main()
