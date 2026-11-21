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
    (r"[A-Za-z]:\\\\", "a Windows path"),
    (r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "an IP address"),
    (r"\b[\w.+-]+@[\w-]+\.[\w.]+\b", "an email address"),
    (r"\b(?:op|binding|grant|dec|env|evt)_[0-9a-f]{32}\b", "a real ID"),
    (r"ssh-(?:ed25519|rsa)\s+AAAA", "a key"),
]

GLOBAL_FLAGS = {"--json", "--non-interactive"}


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


def command_paths(text):
    """The subcommand path of each `heimdall ...` line in a code block."""
    paths = []
    for line in code_lines(text):
        words = line.split()
        if not words or words[0] != "heimdall":
            continue
        path = []
        for w in words[1:]:
            if w in GLOBAL_FLAGS:
                continue
            if w.startswith("-") or w.startswith("<") or w == "--":
                break
            path.append(w)
        if path:
            paths.append(tuple(path))
    return sorted(set(paths))


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
    for pattern, what in FORBIDDEN_TEXT:
        for m in re.finditer(pattern, text, re.I):
            findings.append(f"forbidden: {what} ({m.group(0)!r})")
    code = "\n".join(code_lines(text))
    for pattern, what in FORBIDDEN_CODE:
        for m in re.finditer(pattern, code):
            findings.append(f"forbidden in code: {what} ({m.group(0)!r})")
    for pattern, what in REAL_DATA:
        for m in re.finditer(pattern, text):
            findings.append(f"real-looking data: {what} ({m.group(0)!r})")
    for cmd in command_paths(text):
        if not path_exists(cmd):
            findings.append(f"command not in the CLI: heimdall {' '.join(cmd)}")
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


BAD = """---
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
    echo yes | heimdall time confirm --home /home/example/x
    send `Attend` then `Decide`
    cat ~/.ssh/config; sqlite3 heimdall.db; 10.0.0.1; a@b.example
"""


def self_check():
    findings = lint(BAD, lambda path: path[0] != "frobnicate")
    expected = [
        "group headings", "approval command", "time confirmation", "home override",
        "SSH directory", "private database", "answering a confirmation",
        "the Decide message", "the Attend message", "an absolute path", "an IP address",
        "an email address", "a real ID", "command not in the CLI: heimdall frobnicate",
    ]
    missing = [e for e in expected if not any(e in f for f in findings)]
    if missing:
        print("skill-lint: self-check failed; rules that did not fire: " + ", ".join(missing))
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
