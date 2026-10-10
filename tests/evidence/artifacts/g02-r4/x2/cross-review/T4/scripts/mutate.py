#!/usr/bin/env python3
"""Make two mutants of a T4 cell tree (run with python3 -I).

Usage: mutate.py <cell-tree> <out-dir-prefix> <go|rust> <cell-name> [variants, default seed,nocheck]
Writes <prefix>.seed and <prefix>.nocheck (copies of the cell tree), each with one production
change and the cell's tests untouched:

  seed     the seeded bug is put back (Go: Load's pre-check uses os.Lstat again; Rust:
           read_bounded's pre-check uses symlink_metadata again). The cell's own tests should
           fail: this is the spec's "add or adjust tests so that the bug cannot come back".
  nocheck  the authoritative check on the OPENED descriptor is disabled (Go: fstat IsRegular +
           os.SameFile; Rust: the Unix meta.is_file() check after the open). Only a
           check-then-open race reaches that code once the pre-check follows links, so this
           shows whether any cell test guards it, and gives the TOCTOU probe a positive control.

Every substitution must match exactly once, else the script exits 1 and writes nothing usable.
"""
import re
import shutil
import sys

tree, prefix, lang, cell = sys.argv[1:5]
variants = sys.argv[5].split(",") if len(sys.argv) > 5 else ["seed", "nocheck"]


def sub_once(path, pattern, repl, flags=0):
    text = open(path, encoding="utf-8").read()
    new, n = re.subn(pattern, repl, text, flags=flags)
    if n != 1:
        sys.exit("%s: pattern matched %d times: %r" % (path, n, pattern))
    open(path, "w", encoding="utf-8").write(new)


for variant in variants:
    dst = "%s.%s" % (prefix, variant)
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(tree, dst, symlinks=True)
    if lang == "go":
        f = dst + "/internal/profile/profile.go"
        if variant == "seed":
            if cell.endswith("sonnet1"):
                # remove the follow-the-link block, leaving the Lstat result in st
                sub_once(f, r"\n\tif st\.Mode\(\)&os\.ModeSymlink != 0 \{\n(?:.*\n)*?\t\}\n", "\n")
            else:
                sub_once(f, r"st, err := os\.Stat\(path\)", "st, err := os.Lstat(path)")
        else:
            sub_once(f, r"if err != nil \|\| !fst\.Mode\(\)\.IsRegular\(\) \|\| !os\.SameFile\(st, fst\) \{",
                     "if err != nil {")
    else:
        f = dst + "/src/profile.rs"
        if variant == "seed":
            if cell.endswith("sonnet1"):
                sub_once(f, r"\n    if let Ok\(m\) = &checked\n        && m\.file_type\(\)\.is_symlink\(\)\n    \{\n"
                            r"        checked = std::fs::metadata\(path\);\n    \}\n", "\n")
                sub_once(f, r"let mut checked = ", "let checked = ")
            else:
                sub_once(f, r"if let Ok\(m\) = std::fs::metadata\(path\)", "if let Ok(m) = std::fs::symlink_metadata(path)")
        else:
            sub_once(f, r"\n    if !meta\.is_file\(\) \{\n", "\n    if false && !meta.is_file() {\n")
    print("wrote", dst)
