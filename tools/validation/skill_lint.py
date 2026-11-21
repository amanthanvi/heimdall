#!/usr/bin/env python3
"""Lint the optional agent skill (skills/heimdall/SKILL.md; M07 plan §5, U4).

The skill is guidance only (R-AP-08): it may name the six primitive groups and
read-only commands, and it must never contain an approval, a confirmation, a way
around the boundary, or a real host, path or key. This script checks that, and that
every `heimdall ...` command line in a code block names a command path the given
binary actually has (`<bin> <path> --help` exits 0), so the skill cannot drift from
the installed CLI.

A self-check first runs every rule against a known-bad skill text and requires each
rule to fire, so a lint that accepts everything cannot pass.

Usage: python3 -I tools/validation/skill_lint.py [--heimdall BIN] [SKILL.md]
Exit: 0 clean, 1 findings (or a failed self-check), 2 usage (missing file or binary).
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_SKILL = os.path.join(ROOT, "skills", "heimdall", "SKILL.md")
DEFAULT_BIN = os.path.join(ROOT, "target", "debug", "heimdall")

MAX_LINES = 120
GROUPS = ["inspect", "ensure", "bind", "delegate", "observe", "release / revoke"]

# Anywhere in the text (case-insensitive): approvals, confirmations, policy widening,
# boundary escapes and private state.
FORBIDDEN_TEXT = [
    (r"decision\s+approve", "an approval command"),
    (r"decision\s+deny", "a denial command"),
    (r"time\s+confirm", "a time confirmation command"),
    (r"access\s+allow", "a policy-widening command"),
    (r"access\s+resume", "a policy-resume command"),
    (r"--clear\b", "clearing a cutoff"),
    (r"--home\b", "a home override"),
    (r"HEIMDALL_TEST_", "a test-configuration variable"),
    (r"instance\.json", "a private runtime file"),
    (r"sqlite|\.db\b", "the private database"),
    (r"~/\.ssh|\.ssh/", "the SSH directory"),
    (r"\byes\b", "answering a confirmation"),
]

# Inside code (indented or fenced blocks, and inline backticks): protocol messages an
# agent must never send.
FORBIDDEN_CODE = [
    (r"\bDecide\b", "the Decide message"),
    (r"\bConfirmTime\b", "the ConfirmTime message"),
    (r"\bAttend\b", "the Attend message"),
]

# Real-looking data: placeholders (`<...>`) only.
REAL_DATA = [
    (r"(?<![<\w])/(?:Users|home|root|etc|var|tmp|private)/", "an absolute path"),
    (r"\b[A-Za-z]:\\", "a Windows path"),
    (r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "an IP address"),
    (r"\b[\w.+-]+@[\w-]+\.[\w.]+\b", "an email address"),
    (r"\b(?:op|binding|grant|dec|env|evt)_[0-9a-f]{32}\b", "a real ID"),
    (r"ssh-(?:ed25519|rsa)\s+AAAA", "a key"),
]

GLOBAL_FLAGS = {"--json", "--non-interactive"}

# ⟨M07-W0-R10⟩ The only command paths a skill may name: the six groups, plus the named
# discovery and human-handoff paths (read-only). A command the CLI has but this table lacks
# (an owner-only management command, for example) is a finding. Each path lists every flag
# the skill may use with it; anything else is a finding.
ALLOWED = {
    ("inspect",): set(),
    ("access", "ensure"): {"--profile", "--work-id", "--request-id", "--pair", "--environment",
                           "--until", "--for", "--async", "--timeout-ms"},
    ("run",): {"--profile", "--work-id", "--request-id", "--parent-binding", "--scope",
               "--until", "--"},
    ("access", "delegate"): {"--parent", "--work-id", "--request-id", "--pair", "--until"},
    ("operation", "show"): set(),
    ("operation", "wait"): {"--timeout-ms"},
    ("operation", "events"): {"--operation", "--cursor", "--limit", "--follow", "--max-events"},
    ("operation", "cancel"): set(),
    ("access", "release"): set(),
    ("access", "revoke"): {"--request-id"},
    # Discovery.
    ("schema", "show"): set(),
    # Human handoff: where Heimdall itself shows the decision. Read-only.
    ("decision", "list"): set(),
    ("tui",): set(),
}


def code_lines(text):
    """Lines inside code: 4-space indented blocks, fenced blocks; plus inline spans."""
    out = []
    fenced = False
    for line in text.splitlines():
        if line.strip().startswith("```"):
            fenced = not fenced
            continue
        if fenced or line.startswith("    "):
            out.append(line.strip())
    out.extend(re.findall(r"`([^`]+)`", text))
    return out


def commands(text):
    """Each `heimdall ...` invocation in code: (subcommand path, its flags, 1-based line)."""
    found = []
    fenced = False
    spans = []
    for n, line in enumerate(text.splitlines(), 1):
        if line.strip().startswith("```"):
            fenced = not fenced
            continue
        if fenced or line.startswith("    "):
            spans.append((n, line.strip()))
        spans.extend((n, span) for span in re.findall(r"`([^`]+)`", line))
    for n, span in spans:
        words = span.split()
        if not words or words[0] != "heimdall":
            continue
        rest = [w for w in words[1:] if w not in GLOBAL_FLAGS]
        path = []
        while rest and not rest[0].startswith(("-", "<")):
            path.append(rest.pop(0))
        # `inspect <subject>` and `schema show <name>` take a literal operand.
        for known in sorted(ALLOWED, key=len, reverse=True):
            if tuple(path[:len(known)]) == known:
                path = path[:len(known)]
                break
        flags = []
        for w in rest:
            if w == "--":
                flags.append(w)
                break
            if w.startswith("-"):
                flags.append(w.split("=", 1)[0])
        if not path and not flags:
            continue  # the bare program name in prose
        found.append((tuple(path), flags, n))
    return found


def lint(text, path_exists):
    findings = []
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        findings.append(f"{len(lines)} lines, above the {MAX_LINES}-line cap")
    if not re.match(r"^---\nname: \S+\ndescription: .+\n---\n", text):
        findings.append("front matter must start the file with `name:` and `description:`")
    section = re.search(r"^## The six groups\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    if not section:
        findings.append("no `## The six groups` section")
    else:
        heads = re.findall(r"^### (.+)$", section.group(1), re.M)
        if heads != GROUPS:
            findings.append(f"group headings {heads} are not exactly {GROUPS}")
    # A match is reported by line number and rule only: its value (a path, an ID, a key)
    # is never echoed into the lint's output.
    def line_of(source, m):
        return source.count("\n", 0, m.start()) + 1

    for pattern, what in FORBIDDEN_TEXT:
        for m in re.finditer(pattern, text, re.I):
            findings.append(f"line {line_of(text, m)}: forbidden: {what}")
    for n, line in enumerate(lines, 1):
        code = " ".join(code_lines(line + "\n")) if "`" in line or line.startswith("    ") else ""
        for pattern, what in FORBIDDEN_CODE:
            if re.search(pattern, code):
                findings.append(f"line {n}: forbidden in code: {what}")
    for pattern, what in REAL_DATA:
        for m in re.finditer(pattern, text):
            findings.append(f"line {line_of(text, m)}: real-looking data: {what}")
    for path, flags, n in commands(text):
        if path not in ALLOWED:
            findings.append(f"line {n}: command outside the six groups and the named "
                            f"discovery and handoff paths")
            continue
        if not path_exists(path):
            findings.append(f"line {n}: command not in the CLI")
        for flag in flags:
            if flag not in ALLOWED[path]:
                findings.append(f"line {n}: flag not allowed for this command")
    return findings


def binary_checker(binary):
    scratch = tempfile.mkdtemp(prefix="hm-skill-lint-", dir="/tmp")
    home = os.path.join(scratch, "home")
    hh = os.path.join(scratch, "hh")
    ssh_home = os.path.join(scratch, "ssh")
    for d in (home, hh, os.path.join(ssh_home, "etc-ssh")):
        os.makedirs(d, mode=0o700)
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": home,
        "HEIMDALL_HOME": hh,
        "HEIMDALL_TEST_SSH_HOME": ssh_home,
        "LANG": "C",
    }
    cache = {}

    def exists(path):
        if path not in cache:
            p = subprocess.run([binary, *path, "--help"], env=env, cwd=scratch,
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
            cache[path] = p.returncode == 0
        return cache[path]

    return exists, scratch


BAD = r"""---
name: bad
description: a bad skill
---
## The six groups
### inspect
### ensure
### bind
### delegate
### observe
### release / revoke
### extra

    heimdall decision approve dec_0123456789abcdef0123456789abcdef
    heimdall frobnicate --json
    heimdall destination remove <alias>
    heimdall --json operation wait <operation-id> --no-such-flag
    copy C:\Temp\x
    echo yes | heimdall time confirm --home /home/example/x
    send `Attend` then `Decide`
    cat ~/.ssh/config; sqlite3 heimdall.db; 10.0.0.1; a@b.example
"""


def self_check():
    findings = lint(BAD, lambda path: True)
    expected = [
        "group headings", "an approval command", "a time confirmation command",
        "a home override", "the SSH directory", "the private database",
        "answering a confirmation", "the Decide message", "the Attend message",
        "an absolute path", "an IP address", "an email address", "a real ID",
        # ⟨M07-W0-R10⟩ The three bypasses the W0 review found: an owner-only command the CLI
        # has, a flag outside the table, and an ordinary single-backslash Windows path.
        "command outside the six groups", "flag not allowed", "a Windows path",
    ]
    missing = [e for e in expected if not any(e in f for f in findings)]
    # No finding may echo a matched value.
    leaked = [f for f in findings if "0123456789abcdef" in f or "someone" in f or "Temp" in f]
    if missing or leaked:
        print("skill-lint: self-check failed; rules that did not fire: " + ", ".join(missing)
              + ("; a finding echoed a matched value" if leaked else ""))
        return False
    # A command in the table that the binary lacks is still a finding.
    absent = lint("---\nname: x\ndescription: y\n---\n## The six groups\n"
                  + "".join(f"### {g}\n" for g in GROUPS) + "\n    heimdall tui\n",
                  lambda path: False)
    if not any("command not in the CLI" in f for f in absent):
        print("skill-lint: self-check failed; a missing command was accepted")
        return False
    return True


def main(argv):
    binary = DEFAULT_BIN
    skill = DEFAULT_SKILL
    args = list(argv)
    while args:
        a = args.pop(0)
        if a == "--heimdall" and args:
            binary = os.path.abspath(args.pop(0))
        else:
            skill = a
    if not self_check():
        return 1
    if not os.path.isfile(skill):
        print(f"skill-lint: no skill file at {skill}")
        return 2
    if not os.access(binary, os.X_OK):
        print(f"skill-lint: no heimdall binary at {binary} (build it first, or pass --heimdall)")
        return 2
    with open(skill, encoding="utf-8") as f:
        text = f.read()
    exists, scratch = binary_checker(binary)
    try:
        findings = lint(text, exists)
    finally:
        shutil.rmtree(scratch)
    for f in findings:
        print(f"skill-lint: {f}")
    print(f"skill-lint: {len(findings)} finding(s) in {os.path.relpath(skill, ROOT)}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
