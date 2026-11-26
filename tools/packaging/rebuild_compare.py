#!/usr/bin/env python3
"""Compare the archives produced by rebuild-compare.sh and write its evidence record."""

import datetime
import gzip
import hashlib
import json
from pathlib import Path
import platform
import runpy
import sys
import tarfile
import tempfile


def first_difference(left, right):
    offset = 0
    while True:
        a, b = left.read(1 << 20), right.read(1 << 20)
        if a == b:
            if not a:
                return None
            offset += len(a)
        else:
            return offset + next((i for i, (x, y) in enumerate(zip(a, b)) if x != y),
                                 min(len(a), len(b)))


def member_at(archive, offset):
    with tarfile.open(archive, "r:gz") as tar:
        for item in tar:
            end = item.offset_data + ((item.size + 511) // 512) * 512
            if item.offset <= offset < end:
                if offset < item.offset_data:
                    return item.name, "header", offset - item.offset
                return item.name, "data or padding", offset - item.offset_data
    return None, "tar trailer", offset


def describe_difference(left, right, offset):
    with gzip.open(left) as a, gzip.open(right) as b:
        tar_offset = first_difference(a, b)
    detail = {"archive_offset": offset}
    if tar_offset is None:
        return {**detail, "member": None, "region": "gzip encoding or metadata", "offset": offset}
    for archive in (left, right):
        member, region, relative_offset = member_at(archive, tar_offset)
        if member is not None:
            break
    return {**detail, "tar_offset": tar_offset, "member": member, "region": region, "offset": relative_offset}


def compare(left, right):
    with left.open("rb") as a, right.open("rb") as b:
        offset = first_difference(a, b)
        digests = []
        for fh in (a, b):
            fh.seek(0)
            digests.append(hashlib.file_digest(fh, "sha256").hexdigest())
    observed = {"identical": offset is None, "sha256": digests,
                "archive_bytes": [left.stat().st_size, right.stat().st_size]}
    if offset is not None:
        observed["first_difference"] = describe_difference(left, right, offset)
    return observed


def record(left, right, target, commit, started, out, first_exit, second_exit):
    build_exits = [int(first_exit), int(second_exit)]
    evidence = {
        "case_id": "M08-U4b-same-host-rebuild",
        "status": "implemented_unverified",
        "requirement_ids": ["R-DI-05"],
        "build_commit": commit,
        "artifact_digest": None,
        "environment": {"target": target, "os": platform.system(),
                        "os_release": platform.mac_ver()[0] or platform.release(),
                        "architecture": platform.machine()},
        "provider_versions": [],
        "started_at": started,
        "commands_or_harness": "tools/packaging/rebuild-compare.sh via tools/packaging/build-release.sh",
        "observed_result": {"archive": Path(left).name, "build_exits": build_exits,
                            "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")},
        "evidence_paths": [out],
        "limitations": ["Two checkout paths on one host", "Static archive comparison; no release executable ran"],
    }
    observed = evidence["observed_result"]
    code = 2
    if any(build_exits):
        observed["result"] = "build_failed"
    else:
        try:
            observed.update(compare(Path(left), Path(right)))
        except (OSError, EOFError, tarfile.TarError) as exc:
            observed.update(result="comparison_failed", error=type(exc).__name__)
        else:
            if observed["identical"]:
                observed["result"] = "pass"
                evidence["status"] = "verified"
                evidence["artifact_digest"] = observed["sha256"][0]
                code = 0
            else:
                observed["result"] = "fail"
                code = 1
    output = json.dumps(evidence, indent=2, sort_keys=True)
    Path(out).write_text(output + "\n", encoding="utf-8")
    print(output)
    return code


def self_test():
    here = Path(__file__).resolve().parent
    pack = runpy.run_path(str(here / "provenance.py"))["pack"]
    validator = runpy.run_path(str(here.parents[1] / "tests/g02/minischema.py"))["validate"]
    schema = json.loads((here.parents[1] / "tests/evidence/record.schema.json").read_text(encoding="utf-8"))
    stamp = "2026-11-26T00:00:00Z"
    with tempfile.TemporaryDirectory(prefix="hm-rebuild-test-") as tmp:
        root = Path(tmp)
        stage = root / "release"
        stage.mkdir()
        member = stage / "member.txt"
        left, right, wrapper = (root / name for name in ("left.tar.gz", "right.tar.gz", "wrapper.tar.gz"))
        member.write_bytes(b"abcde")
        pack(str(stage), str(left), stamp)
        payload = gzip.decompress(left.read_bytes())
        wrapper.write_bytes(gzip.compress(payload, mtime=1))
        member.write_bytes(b"abXde")
        pack(str(stage), str(right), stamp)
        detail = compare(left, right)["first_difference"]
        gzip_detail = compare(left, wrapper)["first_difference"]
        checks = {
            "matching archives": compare(left, left)["identical"],
            "differing member and offset": (detail["member"], detail["offset"]) == ("release/member.txt", 2),
            "gzip metadata only": gzip_detail["member"] is None and gzip_detail["offset"] == 4,
        }
        import contextlib
        import io
        for a, b, build_exits, result, want in ((left, left, (0, 0), "pass", 0),
                                               (left, right, (0, 0), "fail", 1),
                                               (left, right, (2, 0), "build_failed", 2)):
            out = root / "evidence.json"
            with contextlib.redirect_stdout(io.StringIO()):
                code = record(a, b, "aarch64-apple-darwin", "a" * 40, stamp, str(out), *build_exits)
            observed = json.loads(out.read_text(encoding="utf-8"))
            checks[result] = (code == want and not validator(schema, observed)
                              and observed["observed_result"]["result"] == result)
    for name, ok in checks.items():
        if not ok:
            print(f"rebuild-compare self-test FAILED: {name}")
    print(f"rebuild-compare self-test: {len(checks)} checks, {sum(not ok for ok in checks.values())} failed")
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(self_test() if sys.argv[1:] == ["--self-test"] else record(*sys.argv[1:]))
