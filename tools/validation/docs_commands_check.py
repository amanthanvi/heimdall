#!/usr/bin/env python3
"""Check that the commands named in the user runbooks exist (m08-plan U7a).

Usage: python3 -I tools/validation/docs_commands_check.py [--self-test] [FILE...]
       (no FILE: every .md under docs/operations, docs/user and docs/security, plus
       docs/compatibility/policy.md and docs/release-notes/v1-candidate.md)
Exit code: 0 when every command resolves; 1 when one does not, or a self-test fails;
2 on a usage error or a missing help golden.

What it reads: `heimdall <command> [<subcommand>]` wherever it appears in a fenced code
block or an inline code span. The first word must be a command in the CLI's top-level help
golden (tests/contracts/golden/cli-help/top-level.txt). When a golden exists for that
command (cli-help/<command>.txt) and lists subcommands, the second word, if it is not a
flag or a placeholder, must be one of them. Commands without a golden are checked at the
top level only; that gap closes with M07's command-tree golden.

A fenced block opened with ```planned holds commands that do not exist yet (ADR-0014
section 7). They are not checked; they are counted and printed, so a planned command that
has since landed is visible as still marked planned.
"""
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GOLDEN = os.path.join(REPO, "tests", "contracts", "golden", "cli-help")
DEFAULT_DIRS = ["docs/operations", "docs/user", "docs/security"]
DEFAULT_FILES = ["docs/compatibility/policy.md", "docs/release-notes/v1-candidate.md"]
CMD = re.compile(r"\bheimdall((?:\s+[^\s`|;&]+){0,2})")


def commands_in(help_text):
    out, on = set(), False
    for line in help_text.splitlines():
        if line.strip() == "Commands:":
            on = True
            continue
        if on:
            if not line.startswith("  "):
                break
            out.add(line.split()[0])
    return out - {"help"}


def load_tree(golden=GOLDEN):
    with open(os.path.join(golden, "top-level.txt"), encoding="utf-8") as fh:
        top = commands_in(fh.read())
    sub = {}
    for name in sorted(top):
        path = os.path.join(golden, name + ".txt")
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as fh:
                found = commands_in(fh.read())
            if found:
                sub[name] = found
    return top, sub


def spans(text):
    """Yield (kind, code) for fenced blocks and inline spans; kind is 'planned' or 'code'."""
    fence, kind, buf = False, "code", []
    for line in text.splitlines():
        if line.startswith("```"):
            if fence:
                yield kind, "\n".join(buf)
                fence, buf = False, []
            else:
                fence, kind = True, ("planned" if line[3:].strip() == "planned" else "code")
            continue
        if fence:
            buf.append(line)
        else:
            for m in re.finditer(r"`([^`]+)`", line):
                yield "code", m.group(1)


def check(text, top, sub):
    problems, planned = [], 0
    for kind, code in spans(text):
        for m in CMD.finditer(code):
            words = m.group(1).split()
            if kind == "planned":
                planned += 1
                continue
            words = [w for w in words if not w.startswith("-")]
            if not words or words[0].startswith(("<", "[")) or not re.match(r"^[a-z][a-z-]*$", words[0]):
                continue  # `heimdall` alone, a placeholder, a file name such as heimdall.previous
            if m.group(1)[:1] not in (" ", "\t"):
                continue
            if words[0] not in top:
                problems.append(f"unknown command: heimdall {words[0]}")
                continue
            if len(words) > 1 and words[0] in sub and re.match(r"^[a-z][a-z-]*$", words[1]):
                if words[1] not in sub[words[0]]:
                    problems.append(f"unknown subcommand: heimdall {words[0]} {words[1]}")
    return problems, planned


def self_test():
    top, sub = {"setup", "enroll", "service"}, {"enroll": {"status", "remove"}}
    cases = [
        ("known", "Run `heimdall setup`.", [], 0),
        ("unknown command", "Run `heimdall frobnicate`.", ["unknown command: heimdall frobnicate"], 0),
        ("unknown subcommand", "```\nheimdall enroll explode <x>\n```", ["unknown subcommand: heimdall enroll explode"], 0),
        ("placeholder argument", "`heimdall enroll remove <enrollment>`", [], 0),
        ("no golden for the command", "`heimdall service anything`", [], 0),
        ("planned is not checked, and is counted", "```planned\nheimdall state restore --backup <f>\n```", [], 1),
        ("a file name is not a command", "kept as `heimdall.previous`", [], 0),
        ("prose is not code", "heimdall frobnicate in prose", [], 0),
        ("a flag first", "`heimdall --json status`", ["unknown command: heimdall status"], 0),
    ]
    bad = 0
    for name, text, want, want_planned in cases:
        got, planned = check(text, top, sub)
        if got != want or planned != want_planned:
            bad += 1
            print(f"self-test FAILED: {name}: {got} planned={planned}")
    print(f"docs_commands_check self-test: {len(cases)} cases, {bad} failed")
    return 1 if bad else 0


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    try:
        top, sub = load_tree()
    except OSError:
        print("docs_commands_check: the CLI help goldens were not found")
        return 2
    files = argv
    if not files:
        files = list(DEFAULT_FILES)
        for d in DEFAULT_DIRS:
            full = os.path.join(REPO, d)
            if os.path.isdir(full):
                files += [os.path.join(d, f) for f in sorted(os.listdir(full)) if f.endswith(".md")]
    bad = total_planned = 0
    for f in files:
        path = f if os.path.isabs(f) else os.path.join(REPO, f)
        try:
            with open(path, encoding="utf-8") as fh:
                problems, planned = check(fh.read(), top, sub)
        except OSError:
            print(f"docs_commands_check: cannot read {f}")
            return 2
        total_planned += planned
        for p in problems:
            bad += 1
            print(f"FAIL {f}: {p}")
    print(f"docs_commands_check: {len(files)} files, {bad} unknown, {total_planned} planned (unchecked)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
