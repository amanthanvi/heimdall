#!/usr/bin/env python3
"""Positive control for the T3 hidden tests (validation only): reference_impl.py with pc_tui.py."""
import os
import sys
sys.dont_write_bytecode = True   # fix round 2: never write __pycache__ (it embeds the home path)

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(HERE, "ref"))
sys.path.insert(0, HERE)
import reference_impl as R  # noqa: E402


def cmd_tui(args):
    flags = R.parse_flags(args, {"--file"}, set(), False)
    if "--file" not in flags:
        R.usage("missing --file", False)
    import pc_tui
    prof = R.load_profile_file(flags["--file"])
    sys.exit(pc_tui.run(prof["destinations"], R.MUT, R.usage))


R.cmd_tui = cmd_tui
R.main()
