#!/usr/bin/env python3
"""Positive control for the T2 hidden tests (validation only; never shown to implementers).

tests/g02/reference_impl.py (byte copy in ref/) plus `profile lint` from ../t2/lint_ref.py.
Proves the T2 tests can be passed by an implementation of specs/T2.md."""
import os
import sys
sys.dont_write_bytecode = True   # fix round 2: never write __pycache__ (it embeds the home path)

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(HERE, "ref"))
sys.path.insert(0, os.path.join(HERE, "..", "t2"))
import reference_impl as R  # noqa: E402
import lint_ref  # noqa: E402

_orig = R.cmd_profile


def cmd_profile(args):
    if not args or args[0] != "lint":
        return _orig(args)
    use_json = "--json" in args
    flags = R.parse_flags(args[1:], {"--file"}, {"--json"}, use_json)
    if "--file" not in flags:
        R.usage("missing --file", use_json)
    prof = R.load_profile_file(flags["--file"])
    data = lint_ref.lint(prof)
    code = "LINT_FINDINGS" if data["findings"] else "LINT_CLEAN"
    rc = 3 if data["findings"] else 0
    if use_json:
        R.out_json(R.result("succeeded", code, data), rc)
    sys.exit(rc)


R.cmd_profile = cmd_profile
R.main()
