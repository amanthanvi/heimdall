#!/usr/bin/env python3
"""Which tests a cross-built test binary contains, read from its own symbols.

Usage (from the repository root, with `python3 -I`):
  platform-tests.py --build-json SHIM/build.json --listed-from DIR [--out report.json]

A test binary built for another platform cannot be listed (`--list`) on the build host,
and `#[cfg(...)]` decides which tests exist on each platform. Every test function a
binary contains has a Rust v0 symbol `_RNv(Nt)*C<crate><module>...<name>` in its
symbol table and debug information, and a function that `cfg` removed has none. So:

  * present: a build-host test (from DIR/<target>.txt, `--list` output names) whose
    symbol is in the binary;
  * absent: one whose symbol is not (cfg-gated off on that platform);
  * extra: a function path in the binary, not listed on the build host, whose name is a
    `#[test]`/`#[tokio::test]` function somewhere in the sources (a platform-only test).

The report is input for the case index's `platform_only` entries; it is an analysis
aid, never evidence that a test ran.
"""

import argparse
import json
import re
import sys
from pathlib import Path

TEST_FN = re.compile(r"#\[(?:tokio::)?test(?:\([^]]*\))?\]\s*(?:#\[[^]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)")


def ident(name):
    """The v0 encoding of one ASCII identifier: <len>[_]<ident>."""
    sep = "_" if name[0].isdigit() or name[0] == "_" else ""
    return f"{len(name)}{sep}{name}"


def parse_ident(data, i):
    """(identifier, next index) of a v0 <disambiguator>? <len> [_] <bytes> at i, or None."""
    n = len(data)
    if i < n and data[i:i + 1] == b"s":
        j = i + 1
        while j < n and (chr(data[j]).isalnum()):
            j += 1
        if j < n and data[j:j + 1] == b"_":
            i = j + 1
        else:
            return None
    j = i
    while j < n and 48 <= data[j] <= 57:
        j += 1
    if j == i:
        return None
    length = int(data[i:j])
    if data[j:j + 1] == b"_":
        j += 1
    word = data[j:j + length]
    if len(word) != length or not re.fullmatch(rb"[A-Za-z_][A-Za-z0-9_]*", word):
        return None
    return word.decode("ascii"), j + length


def function_paths(data, crate):
    """Every crate-local function path (tuple of identifiers after the crate) of `crate`."""
    out = set()
    start = 0
    tag = b"_RNv"
    while True:
        i = data.find(tag, start)
        if i < 0:
            return out
        start = i + 1
        j = i + len(tag)
        depth = 0
        while data[j:j + 2] == b"Nt":
            depth += 1
            j += 2
        if data[j:j + 1] != b"C":
            continue
        r = parse_ident(data, j + 1)
        if not r or r[0] != crate:
            continue
        j = r[1]
        path = []
        for _ in range(depth + 1):
            r = parse_ident(data, j)
            if not r:
                break
            path.append(r[0])
            j = r[1]
        if len(path) == depth + 1:
            out.add(tuple(path))


def source_test_names(root):
    names = set()
    for base in ("tests", "crates"):
        for p in (root / base).rglob("*.rs"):
            if "target" in p.parts:
                continue
            names.update(TEST_FN.findall(p.read_text(encoding="utf-8", errors="replace")))
    return names


def artifacts(build_json):
    out = {}
    for line in Path(build_json).read_text(encoding="utf-8").splitlines():
        try:
            m = json.loads(line)
        except json.JSONDecodeError:
            continue
        if m.get("reason") != "compiler-artifact" or not m.get("executable") or not m["profile"]["test"]:
            continue
        t = m["target"]
        name = t["name"] if "test" in t["kind"] else t["name"] + "-unit"
        out[name] = (t["name"].replace("-", "_"), m["executable"])
    return out


def analyse(arts, listed_dir, root):
    tests_in_sources = source_test_names(root)
    report = {}
    for name, (crate, exe) in sorted(arts.items()):
        data = Path(exe).read_bytes()
        paths = function_paths(data, crate)
        listed_file = Path(listed_dir) / f"{name}.txt"
        listed = listed_file.read_text(encoding="utf-8").split() if listed_file.exists() else []
        present = [t for t in listed if tuple(t.split("::")) in paths]
        absent = [t for t in listed if tuple(t.split("::")) not in paths]
        listed_set = set(listed)
        extra = sorted("::".join(p) for p in paths if p[-1] in tests_in_sources and "::".join(p) not in listed_set)
        report[name] = {"present": len(present), "absent": absent, "extra": extra}
    return report


def compress(target, where, all_platforms):
    """platform_only entries for one target: {key: [platforms]}. Each module prefix
    (and the target itself) gets the platform set most of its tests have, and only the
    tests or sub-modules that differ from it get their own entry; the most specific
    key applies (m02-evidence.py `applicable`)."""
    out = {}
    full = tuple(sorted(all_platforms))

    def walk(prefix, names, inherited):
        counts = {}
        for n in names:
            k = tuple(sorted(where[n]))
            counts[k] = counts.get(k, 0) + 1
        major = max(counts, key=lambda k: (counts[k], k == full))
        if major != inherited:
            out[f"{target}::{prefix}" if prefix else target] = list(major)
            inherited = major
        depth = prefix.count("::")
        children, leaves = {}, []
        for n in names:
            parts = n.split("::")
            if len(parts) > depth + 1:
                children.setdefault("::".join(parts[: depth + 1]) + "::", []).append(n)
            else:
                leaves.append(n)
        for child, members in sorted(children.items()):
            walk(child, members, inherited)
        for n in leaves:
            k = tuple(sorted(where[n]))
            if k != inherited:
                out[f"{target}::{n}"] = list(k)

    if where:
        walk("", sorted(where), full)
    return out


def platform_only(build_host, listed_dir, reports):
    """(platform_only, extras) from the build-host listings and per-platform scans."""
    plats = [build_host] + sorted(reports)
    entries, extras = {}, {}
    targets = sorted(p.stem for p in Path(listed_dir).glob("*.txt"))
    for target in targets:
        listed = (Path(listed_dir) / f"{target}.txt").read_text(encoding="utf-8").split()
        where = {n: {build_host} for n in listed}
        for plat, rep in reports.items():
            r = rep.get(target)
            if r is None:
                continue
            gone = set(r["absent"])
            for n in listed:
                if n not in gone:
                    where[n].add(plat)
            for n in r["extra"]:
                extras.setdefault(plat, {}).setdefault(target, []).append(n)
        missing = [p for p in reports if target not in reports[p]]
        for p in missing:
            for n in listed:
                where[n].discard(p)
        entries.update(compress(target, where, plats))
    # A test only some scanned platforms have beyond the build host's list.
    seen = {}
    for plat, by_target in extras.items():
        for target, names in by_target.items():
            for n in names:
                seen.setdefault((target, n), set()).add(plat)
    only = {}
    for (target, n), ps in sorted(seen.items()):
        only.setdefault(target, {})[n] = sorted(ps)
    return entries, only


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-json")
    ap.add_argument("--listed-from", required=True, help="directory of <target>.txt build-host listings")
    ap.add_argument("--out")
    ap.add_argument("--platform-only", action="store_true",
                    help="combine --report PLATFORM=FILE scans into platform_only entries")
    ap.add_argument("--report", action="append", default=[])
    ap.add_argument("--build-host", default="macos")
    a = ap.parse_args()
    if a.platform_only:
        reports = {}
        for item in a.report:
            plat, path = item.split("=", 1)
            reports[plat] = json.loads(Path(path).read_text(encoding="utf-8"))
        entries, extra = platform_only(a.build_host, a.listed_from, reports)
        report = {"platform_only": entries, "beyond_build_host": extra}
    else:
        if not a.build_json:
            ap.error("--build-json is required for a scan")
        report = analyse(artifacts(a.build_json), a.listed_from, Path.cwd())
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
