#!/usr/bin/env python3
"""The `unsafe` inventory check (m08-plan U1b, for M09-T03's review).

`docs/security/unsafe-inventory.md` lists every Rust module of the repository that allows
`unsafe`, between the markers `<!-- unsafe-inventory:begin -->` and
`<!-- unsafe-inventory:end -->`, one per line: `<path> <kind>`, where kind is

* `allow-module`: the file holds an inner `#![allow(unsafe_code)]` (or `expect`);
* `allow-item`: the file holds an outer `#[allow(unsafe_code)]` (or `expect`) on an item;
* `under:<path>`: the file has `unsafe` code and no allowance of its own; it is a child
  module of `<path>`, whose inner allowance covers it.

This script scans the repository's Rust sources (`crates/`, `tests/` without the evidence
artifacts, `fuzz/`; never `target/`, `prototypes/` or `third_party/`), with comments and
string literals removed, for those allowances and for `unsafe` code (`unsafe` followed by a
block, `fn`, `impl`, `extern` or `trait`, and the `#[unsafe(...)]` attribute form), and
checks the workspace lint configuration: `unsafe_code = "deny"` in the root manifest and
`[lints] workspace = true` in every member.

Usage:
    python3 tools/validation/unsafe_inventory.py --check   exit 0 when the doc's set equals
                                                            the scan and the lints hold
    python3 tools/validation/unsafe_inventory.py --list    print the scan (path, kind,
                                                            counts), informational

Exit codes: 0 pass; 1 a difference or a lint problem (each printed); 2 usage or an
unreadable input. Read-only: it writes nothing.
"""

import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOC = os.path.join("docs", "security", "unsafe-inventory.md")
SCAN_DIRS = ["crates", "tests", "fuzz"]
SKIP_PARTS = {"target", "prototypes", "third_party", ".git"}
SKIP_PREFIXES = [os.path.join("tests", "evidence", "artifacts") + os.sep]
BEGIN = "<!-- unsafe-inventory:begin -->"
END = "<!-- unsafe-inventory:end -->"

ALLOW = re.compile(r"#(!?)\[\s*(?:allow|expect)\s*\(([^\]]*)\)\s*\]")
UNSAFE_CODE = re.compile(r"\bunsafe\s*(?:\{|fn\b|impl\b|extern\b|trait\b)|#\s*\[\s*unsafe\s*\(")


TOKEN = re.compile(
    r"""(?P<line>//[^\n]*)
      | (?P<block>/\*)
      | (?P<raw>b?r(?P<hashes>\#*)")
      | (?P<str>b?"(?:\\.|[^"\\])*")
      | (?P<char>b?'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|.)|[^\\'\n])')""",
    re.X | re.S,
)


def strip(text):
    """`text` with comments and string, byte-string and char literals blanked (newlines
    kept, so positions stay on their lines)."""
    out, pos, n = [], 0, len(text)
    while True:
        m = TOKEN.search(text, pos)
        if not m:
            out.append(text[pos:])
            return "".join(out)
        start = m.start()
        if m.group("raw") and start > 0 and (text[start - 1].isalnum() or text[start - 1] == "_"):
            # An identifier ending in `r` or `br` before a quote is not a raw string.
            out.append(text[pos : start + 1])
            pos = start + 1
            continue
        out.append(text[pos:start])
        if m.group("block"):
            depth, j = 1, m.end()
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            end = j
        elif m.group("raw"):
            close = '"' + m.group("hashes")
            j = text.find(close, m.end())
            end = n if j < 0 else j + len(close)
        else:
            end = m.end()
        out.append("\n" * text.count("\n", start, end))
        pos = end


def rust_files():
    for top in SCAN_DIRS:
        base = os.path.join(ROOT, top)
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_PARTS)
            for name in sorted(filenames):
                if not name.endswith(".rs"):
                    continue
                rel = os.path.relpath(os.path.join(dirpath, name), ROOT)
                if any(rel.startswith(p) for p in SKIP_PREFIXES):
                    continue
                yield rel


def scan():
    """`{path: {"inner": n, "outer": n, "unsafe": n}}` for every file with an allowance or
    `unsafe` code."""
    found = {}
    for rel in rust_files():
        try:
            with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
                text = strip(f.read())
        except (OSError, UnicodeDecodeError) as e:
            sys.exit("unsafe-inventory: cannot read %s: %s" % (rel, e))
        inner = outer = 0
        for m in ALLOW.finditer(text):
            if re.search(r"\bunsafe_code\b", m.group(2)):
                if m.group(1):
                    inner += 1
                else:
                    outer += 1
        count = len(UNSAFE_CODE.findall(text))
        if inner or outer or count:
            found[rel] = {"inner": inner, "outer": outer, "unsafe": count}
    return found


def parent_modules(rel):
    """The files that can declare `rel` as a module, nearest first (`a/b/c.rs` is declared by
    `a/b/mod.rs` or `a/b.rs`; `a/b/mod.rs` by `a/mod.rs` or `a.rs`)."""
    d = os.path.dirname(rel)
    if os.path.basename(rel) == "mod.rs":
        d = os.path.dirname(d)
    while d and d not in SCAN_DIRS:
        yield os.path.join(d, "mod.rs")
        yield d + ".rs"
        d = os.path.dirname(d)


def entries(found):
    """The inventory lines the scan implies, and the files with `unsafe` code no allowance
    covers."""
    lines, uncovered = set(), []
    for rel, c in sorted(found.items()):
        if c["inner"]:
            lines.add((rel, "allow-module"))
        if c["outer"]:
            lines.add((rel, "allow-item"))
        if c["unsafe"] and not c["inner"] and not c["outer"]:
            parent = next((p for p in parent_modules(rel) if found.get(p, {}).get("inner")), None)
            if parent:
                lines.add((rel, "under:" + parent))
            else:
                uncovered.append(rel)
    return lines, uncovered


def doc_entries():
    path = os.path.join(ROOT, DOC)
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        sys.exit("unsafe-inventory: cannot read %s: %s" % (DOC, e))
    if BEGIN not in text or END not in text:
        sys.exit("unsafe-inventory: %s has no %s ... %s block" % (DOC, BEGIN, END))
    block = text.split(BEGIN, 1)[1].split(END, 1)[0]
    out = set()
    for line in block.splitlines():
        line = line.strip()
        if not line or line.startswith("```") or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            sys.exit("unsafe-inventory: a malformed inventory line in %s: %r" % (DOC, line))
        out.add((parts[0], parts[1]))
    return out


def lint_problems():
    problems = []
    with open(os.path.join(ROOT, "Cargo.toml"), encoding="utf-8") as f:
        root = f.read()
    lints = root.split("[workspace.lints.rust]", 1)
    if len(lints) != 2 or not re.search(r'^\s*unsafe_code\s*=\s*"deny"', lints[1].split("\n[", 1)[0], re.M):
        problems.append('Cargo.toml: [workspace.lints.rust] does not set unsafe_code = "deny"')
    members = re.search(r"^members\s*=\s*\[(.*?)\]", root, re.S | re.M)
    for member in re.findall(r'"([^"]+)"', members.group(1) if members else ""):
        manifest = os.path.join(ROOT, member, "Cargo.toml")
        try:
            with open(manifest, encoding="utf-8") as f:
                text = f.read()
        except OSError:
            problems.append("%s: no manifest" % member)
            continue
        section = text.split("[lints]", 1)
        if len(section) != 2 or not re.search(r"^\s*workspace\s*=\s*true", section[1].split("\n[", 1)[0], re.M):
            problems.append("%s/Cargo.toml: no [lints] workspace = true (the deny does not apply)" % member)
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.check == args.list:
        ap.print_usage(sys.stderr)
        return 2
    found = scan()
    lines, uncovered = entries(found)
    if args.list:
        for rel, kind in sorted(lines):
            c = found[rel]
            print("%s %s unsafe=%d inner-allow=%d outer-allow=%d" % (rel, kind, c["unsafe"], c["inner"], c["outer"]))
        for rel in uncovered:
            print("%s UNCOVERED unsafe=%d" % (rel, found[rel]["unsafe"]))
        print("total unsafe constructs: %d in %d files" % (sum(c["unsafe"] for c in found.values()), sum(1 for c in found.values() if c["unsafe"])))
        return 0
    documented = doc_entries()
    bad = 0
    for rel, kind in sorted(lines - documented):
        print("unsafe-inventory: not in %s: %s %s" % (DOC, rel, kind))
        bad += 1
    for rel, kind in sorted(documented - lines):
        print("unsafe-inventory: in %s but not found: %s %s" % (DOC, rel, kind))
        bad += 1
    for rel in uncovered:
        print("unsafe-inventory: unsafe code with no allowance covering it: %s" % rel)
        bad += 1
    for p in lint_problems():
        print("unsafe-inventory: %s" % p)
        bad += 1
    if bad:
        print("unsafe-inventory: FAIL (%d)" % bad)
        return 1
    print("unsafe-inventory: PASS (%d entries)" % len(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
