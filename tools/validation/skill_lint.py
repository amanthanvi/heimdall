#!/usr/bin/env python3
"""Lint the optional agent skill (skills/heimdall/SKILL.md; M07 plan §5, U4).

The skill is guidance only (R-AP-08): it may name the six primitive groups and
read-only commands, and it must never contain an approval, a confirmation, a way
around the boundary, or a real host, path or key. This script checks that, and that
every `heimdall ...` command in code names a command path the given binary actually
has (`<bin> <path> --help` exits 0), so the skill cannot drift from the installed CLI.

⟨M07-W1-R05⟩ The Markdown is read in one pass (`scan`), and every code check uses its
result. Code is: a fenced block (backtick or tilde fence of three or more characters, with
or without an info string, closed only by a fence of the same character that is at least
as long; an unclosed fence runs to the end), a line indented by four spaces or a tab, and
an inline span (which may wrap across the lines of a paragraph). A block quote's `>`
markers are removed first, and a fence may open on a list item's first line, so code
inside a quote or a list is read the same way.

A command is one plain invocation. The program name must be the first word of its code
line or span. Anywhere else it is a finding: after a shell prompt (`$ `, `> `, `PS> `),
after `&&`, behind another program, or in prose. A command line with shell syntax
(`&&`, `||`, `;`, `|`, a backtick, `$(`, a redirection, a line continuation) is a finding
as a whole. Findings give a line number and a rule, and never echo the skill's text.

A self-check first runs every rule against known-bad skill text and requires each rule to
fire, so a lint that accepts everything cannot pass.

Usage: python3 -I -B tools/validation/skill_lint.py [--heimdall BIN] [SKILL.md]
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
INSPECT_SUBJECTS = {
    "capabilities", "environments", "profiles", "destinations", "bindings", "grants",
    "operations", "decisions", "identities", "projections", "enrollments", "connections",
    "workspace", "policies",
}
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


QUOTE = re.compile(r"(?: {0,3}>[ \t]?)+")
FENCE = re.compile(r"\s*(?:(?:[-*+]|\d+[.)])\s+)*(`{3,}|~{3,})(.*)")
SPAN = re.compile(r"(?s)(?<!`)(`+)(?!`)(.+?)(?<!`)\1(?!`)")
NAME = r"\bheimdall\b"
PROMPT = re.compile(r"(?:[$>%#]|PS[^>]*>)\s+(?=heimdall\b)")
PLACEHOLDER = re.compile(r"<[a-z][a-z0-9-]*>")
SHELL_SYNTAX = re.compile(r"[;|&`$<>\\]")


def scan(text):
    """One pass over the Markdown, tracking fence state.

    Returns `(code, prose)`. `code` lists every piece of code as `(line, text)`: each line of
    a fenced or indented block, and each inline span (joined to one line, at the line where
    it opens). `prose` lists every other line as `(line, text)` with its inline spans blanked.
    """
    code, prose, paragraph, fence, fence_quoted = [], [], [], None, False

    def flush():  # An inline span may wrap, so spans are found per paragraph.
        joined = "\n".join(line for _, line in paragraph)
        for span in SPAN.finditer(joined):
            code.append((paragraph[joined.count("\n", 0, span.start())][0], " ".join(span[2].split())))
        blanked = SPAN.sub(lambda span: re.sub(r"[^\n]", " ", span[0]), joined)
        prose.extend(zip((n for n, _ in paragraph), blanked.split("\n")))
        paragraph.clear()

    for n, raw in enumerate(text.splitlines(), 1):
        quote = QUOTE.match(raw)
        line = raw[quote.end():] if quote else raw
        if fence:
            # Inside a fence, `> ` is a quote marker only when the fence itself is quoted.
            inner = line if fence_quoted else raw
            if re.fullmatch(rf"\s*{re.escape(fence[0])}{{{len(fence)},}}\s*", inner):
                fence = None
            else:
                code.append((n, inner.strip()))
            continue
        opener = FENCE.match(line)
        # A backtick fence's info string holds no backtick (that is an inline span).
        if opener and not (opener[1][0] == "`" and "`" in opener[2]):
            flush()
            fence, fence_quoted = opener[1], bool(quote)
        elif line.startswith(("    ", "\t")):
            flush()
            code.append((n, line.strip()))
        elif not line.strip():
            flush()
        else:
            paragraph.append((n, line))
    flush()
    return code, prose


def command(snippet):
    """The subcommand path and flags of one `heimdall ...` invocation."""
    rest = [w for w in snippet.split()[1:] if w not in GLOBAL_FLAGS]
    path = []
    while rest and not rest[0].startswith(("-", "<")):
        path.append(rest.pop(0))
    # ⟨M07-W2-R02⟩ Only `inspect <subject>` (a fixed subject list) and `schema show <name>`
    # take one literal operand; a trailing word after any other command stays in the
    # path, so an invented command (`tui destination remove`) is not in the table.
    if len(path) == 2 and path[0] == "inspect" and path[1] in INSPECT_SUBJECTS:
        path = path[:1]
    elif len(path) == 3 and tuple(path[:2]) == ("schema", "show"):
        path = path[:2]
    flags = []
    for w in rest:
        if w == "--":
            flags.append(w)
            break
        if w.startswith("-"):
            flags.append(w.split("=", 1)[0])
    return tuple(path), flags


def lint(text, path_exists):
    findings = []
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        findings.append(f"{len(lines)} lines, above the {MAX_LINES}-line cap")
    front = re.match(r"^---\nname: \S+\ndescription: .+\n---\n", text)
    if not front:
        findings.append("front matter must start the file with `name:` and `description:`")
    code, prose = scan(text)

    # Group headings are reported by line number and expected name, never by their own text.
    inside, found, heads = False, False, []
    for n, line in prose:
        if re.match(r"##(?!#)", line):
            inside = line.rstrip() == "## The six groups"
            found = found or inside
        elif inside and re.match(r"###(?!#)", line):
            heads.append((n, line.rstrip()))
    if not found:
        findings.append("no `## The six groups` section")
    else:
        for i, (n, line) in enumerate(heads):
            if i >= len(GROUPS):
                findings.append(f"line {n}: a group heading beyond the six")
            elif line != f"### {GROUPS[i]}":
                findings.append(f"line {n}: group heading {i + 1} is not `{GROUPS[i]}`")
        if len(heads) < len(GROUPS):
            findings.append(f"{len(heads)} group headings in `## The six groups`, not {len(GROUPS)}")

    # A match is reported by line number and rule only: its value (a path, an ID, a key)
    # is never echoed into the lint's output.
    def line_of(source, m):
        return source.count("\n", 0, m.start()) + 1

    for pattern, what in FORBIDDEN_TEXT:
        for m in re.finditer(pattern, text, re.I):
            findings.append(f"line {line_of(text, m)}: forbidden: {what}")
    for n, snippet in code:
        for pattern, what in FORBIDDEN_CODE:
            if re.search(pattern, snippet):
                findings.append(f"line {n}: forbidden in code: {what}")
    for pattern, what in REAL_DATA:
        for m in re.finditer(pattern, text):
            findings.append(f"line {line_of(text, m)}: real-looking data: {what}")

    # Every mention of the program name is accounted for: it starts a code line or span that
    # holds one plain, allowed invocation, or it is a finding.
    for n, line in prose:
        named = front and n == 2  # The front matter's own `name:` line.
        if re.search(NAME, line) and not named:
            findings.append(f"line {n}: the program name outside code")
    for n, snippet in code:
        prompt = PROMPT.match(snippet)
        if prompt:
            findings.append(f"line {n}: a shell prompt before the command")
            snippet = snippet[prompt.end():]
        starts = snippet.split()[:1] == ["heimdall"]
        if len(re.findall(NAME, snippet, re.I)) > starts:
            findings.append(f"line {n}: the program name is not at the start of its code line or span")
        if not starts:
            continue
        if SHELL_SYNTAX.search(PLACEHOLDER.sub("", snippet)):
            findings.append(f"line {n}: shell syntax in a command line (one plain invocation only)")
            continue
        path, flags = command(snippet)
        if not path and not flags:
            continue  # the bare program name
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
### watchgroup
### release / revoke
### surplusgroup

    heimdall decision approve dec_0123456789abcdef0123456789abcdef
    heimdall frobnicate --json
    heimdall destination remove <alias>
    heimdall --json operation wait <operation-id> --no-such-flag
    copy C:\Temp\x
    echo yes | heimdall time confirm --home /home/example/x
    send `Attend` then `Decide`
    cat ~/.ssh/config; sqlite3 heimdall.db; 10.0.0.1; a@b.example
"""

HEAD = ("---\nname: x\ndescription: y\n---\n## The six groups\n"
        + "".join(f"### {g}\n" for g in GROUPS) + "\n")

# Allowed commands in every form of code, and prose that only looks like a protocol message.
GOOD = HEAD + """```sh
heimdall --json inspect capabilities
```

~~~~
heimdall tui
~~~~

    heimdall --json operation show <operation-id>

Use `heimdall decision list` or the bare `heimdall`, and wait with `heimdall --json
operation wait <operation-id>`. Decide from `code`.
"""

REMOVE = "heimdall destination remove <alias>"  # A command the CLI has and the table lacks.
OUTSIDE = "command outside the six groups"
SYNTAX = "shell syntax in a command line"
# ⟨M07-W1-R05⟩ Each body follows HEAD. The finding must name that line of the body and the rule.
NEGATIVES = [
    # The review's four.
    ("```\nDecide\n```\n", 2, "the Decide message"),
    (f"~~~sh\n{REMOVE}\n~~~\n", 2, OUTSIDE),
    (f"    $ {REMOVE}\n", 1, "a shell prompt"),
    (f"    heimdall --json inspect capabilities && {REMOVE}\n", 1, SYNTAX),
    # A shorter or different fence does not close a fence.
    ("````text\n```\nDecide\n````\n", 3, "the Decide message"),
    (f"~~~\n```\n{REMOVE}\n~~~\n", 3, OUTSIDE),
    # Code inside a block quote and inside a list item.
    ("> ```\n> Decide\n> ```\n", 2, "the Decide message"),
    (">     Decide\n", 1, "the Decide message"),
    (f"- ```\n  {REMOVE}\n  ```\n", 2, OUTSIDE),
    # The other prompts. An unindented `> ` outside a fence is a Markdown quote, so its text is
    # prose. Inside an unquoted fence it is a prompt.
    (f"```\n> {REMOVE}\n```\n", 2, "a shell prompt"),
    (f"    $ {REMOVE}\n", 1, OUTSIDE),
    (f"    > {REMOVE}\n", 1, "a shell prompt"),
    (f"    PS> {REMOVE}\n", 1, "a shell prompt"),
    (f"Run `PS C:> {REMOVE}` now.\n", 1, "a shell prompt"),
    (f"> {REMOVE}\n", 1, "the program name outside code"),
    # The other compound forms.
    ("    heimdall --json inspect capabilities || heimdall tui\n", 1, SYNTAX),
    ("    heimdall --json inspect capabilities; heimdall tui\n", 1, SYNTAX),
    ("    heimdall --json inspect capabilities | sh\n", 1, SYNTAX),
    ("    heimdall --json inspect `id`\n", 1, SYNTAX),
    ("    heimdall --json inspect $(id)\n", 1, SYNTAX),
    ("    heimdall --json inspect capabilities > <file>\n", 1, SYNTAX),
    # The program name behind another program, in another case, and in a span that wraps.
    (f"    sudo {REMOVE}\n", 1, "not at the start"),
    ("    Heimdall destination remove <alias>\n", 1, "not at the start"),
    ("Run `heimdall destination\nremove <alias>` now.\n", 1, OUTSIDE),
    # ⟨M07-W2-R02⟩ Words after an allowed command, and an `inspect` subject not on the list.
    ("    heimdall tui destination remove <alias>\n", 1, OUTSIDE),
    ("    heimdall decision list approve <id>\n", 1, OUTSIDE),
    ("    heimdall inspect secrets\n", 1, OUTSIDE),
]


def self_check():
    findings = lint(BAD, lambda path: True)
    expected = [
        "group heading 5 is not", "a group heading beyond the six",
        "an approval command", "a time confirmation command",
        "a home override", "the SSH directory", "the private database",
        "answering a confirmation", "the Decide message", "the Attend message",
        "an absolute path", "an IP address", "an email address", "a real ID",
        # ⟨M07-W0-R10⟩ The three bypasses the W0 review found: an owner-only command the CLI
        # has, a flag outside the table, and an ordinary single-backslash Windows path.
        OUTSIDE, "flag not allowed", "a Windows path",
    ]
    missing = [e for e in expected if not any(e in f for f in findings)]
    # No finding may echo a matched value or a heading's text.
    echoed = ("0123456789abcdef", "Temp", "example", "frobnicate", "watchgroup", "surplusgroup")
    leaked = [f for f in findings if any(value in f for value in echoed)]
    if missing or leaked:
        print("skill-lint: self-check failed; rules that did not fire: " + ", ".join(missing)
              + ("; a finding echoed a matched value" if leaked else ""))
        return False
    # A command in the table that the binary lacks is still a finding.
    absent = lint(HEAD + "    heimdall tui\n", lambda path: False)
    if not any("command not in the CLI" in f for f in absent):
        print("skill-lint: self-check failed; a missing command was accepted")
        return False
    if lint(GOOD, lambda path: True):
        print("skill-lint: self-check failed; a clean skill has findings")
        return False
    first = HEAD.count("\n")
    for number, (body, line, rule) in enumerate(NEGATIVES, 1):
        found = lint(HEAD + body, lambda path: True)
        if not any(f.startswith(f"line {first + line}: ") and rule in f for f in found):
            print(f"skill-lint: self-check failed; negative {number} was accepted (rule: {rule})")
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
