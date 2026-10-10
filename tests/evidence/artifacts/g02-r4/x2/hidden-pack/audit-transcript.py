#!/usr/bin/env python3
"""Audit an X2 implementer's transcripts for access outside its workspace (fix round 2, 2026-10-06).

usage: python3 -I -B audit-transcript.py --repo REPO_ROOT --workspace OWN_WS
                                         [--workspace-prefix PREFIX ...] [--other-workspace PATH ...]
                                         [--scratch DIR ...] [--json] TRANSCRIPT_OR_DIR...

TRANSCRIPT_OR_DIR is a Claude Code transcript (<home>/.claude/projects/<project>/<session>.jsonl) or a
directory searched recursively for *.jsonl (so <session>/subagents/**/agent-*.jsonl are included) and
for the persisted large tool outputs <session>/tool-results/*.txt.  Give both the session file and the
session directory.  One invocation audits one cell and prints one verdict for it.

Why the rewrite: the first version only searched for known path strings, so it reported CLEAN for
`cd /tmp && diff -r hm-r4/seeded/go ...`, `diff -r ../../hm-r4/seeded/go prototypes/go`,
`diff -r /tmp/hm*/M00*/base/prototypes/go prototypes/go` and `cat ../../x2ws-<other>/...`, and it
did not see that implementers start with their cwd at the repository root (which holds the unseeded
prototypes).  This version is conservative: it works out where every tool call can reach.

For every tool call:
  * The effective cwd is the transcript entry's `cwd` field (the last seen one if absent), updated by
    every `cd`/`pushd` inside a Bash command.  A cd inside a pipeline, after `&`, or before `||` keeps
    the old cwd possible as well; a subshell `( ... )` restores it; `cd -`, `popd` or a target that
    cannot be resolved make the cwd unknown.
  * Bash: the command is tokenized (quotes, escapes, $VAR, ${...}, $(...), backticks, ~, globs,
    redirections, heredocs).  Every argument and redirection target, relative or absolute, is resolved
    against every possible cwd; ~ and $HOME expand to the home directory, $PWD to the cwd, variables
    assigned in the same command (VAR=..., export, for-loops) to their values.  An argument that holds
    an expansion that cannot be resolved ($1, $(...), an unknown variable) is flagged.  A glob is
    resolved to its static prefix and flagged if that prefix is outside the allowed places or if a
    glob component could match `..`.  The whole command text (heredoc bodies, -c code, backticks) is
    also scanned for absolute, ~/, $HOME/ and ../ paths.  Any command other than cd and a few
    builtins that cannot touch files (echo, printf, true, false, exit, sleep, date, which, type) is
    flagged when it runs while a possible cwd is outside the allowed places (e.g. before the agent cd'd
    from the repository root into its workspace), because it may read the cwd implicitly.
  * Read, Write, Edit, MultiEdit, NotebookEdit, LS: the path (relative ones against the cwd).
    Glob and Grep: `path` (default: the cwd) and the pattern / `glob` filter joined to it.
  * Any other tool: every absolute, ~/ or $HOME/ path in its input.
  * Every tool input and every tool output is also searched for marker strings (the repository path,
    this directory and its parent heimdall-m00, r4-hidden, r4-scratch, seeded-trees, /tmp/hm-r4,
    taskpack, g02-r4/x2, GitRepos/heimdall, other workspaces).  A marker in a tool output flags the
    call that produced it.

Allowed places: the own --workspace and everything under it, its parent directory itself (not its
other children), every --scratch directory (e.g. the cell's own Claude Code session directory), and
the toolchain and system locations below (go/cargo/rustup/zig caches and installs, /usr, /bin,
/sbin, /opt/homebrew, /Library/Developer, Xcode and Docker app bundles, /System, /dev,
/private/var/folders for compiler temp files, ~/.docker for the docker CLI).  A path holding a marker
is flagged even inside an allowed place.  Comparison is case-insensitive (APFS) and folds
/private/tmp, /private/var and /private/etc to /tmp, /var and /etc.

Output: no transcript text, only indices, line numbers, tool names and reason codes:
  CALL <index> <file> line <n> <tool>: <reason>,...   one line per offending tool call
  ENTRY <file> line <n>: <reason>,...                 a marker in an entry that is not a tool call
                                                      or tool output we can attribute (e.g. persisted)
  NOTE <file> line <n>: <reason>,...                  a marker in prompt or assistant text (does not
                                                      change the verdict: mentioning is not reaching)
  VERDICT CLEAN | VERDICT SUSPECT calls [<index>, ...] entries <count>
Reason codes: cwd-outside:<class>, cwd-unknown, path-outside:<class>, glob-outside:<class>,
unresolved-expansion, unparsed-command, marker:<category>, output-marker:<category>; <class> is one
of repository, hidden, other-workspace, tmp, home, root, outside.  --json prints the same as one JSON
object.  Exit status: 0 CLEAN; 1 SUSPECT (inspect those calls by hand and decide whether the cell is
contaminated); 2 usage error.
"""
import sys
sys.dont_write_bytecode = True
import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import posixpath  # noqa: E402
import re  # noqa: E402
from pathlib import Path  # noqa: E402

HERE = Path(__file__).resolve().parent
HOME = os.path.expanduser("~").rstrip("/")
SENT = {"*": "\ue000", "?": "\ue001", "[": "\ue002", "{": "\ue003"}   # unquoted glob characters
SENTS = set(SENT.values())
UNK = "\x00unknown-cwd"          # a cwd that cannot be determined
HARMLESS = {"echo", "printf", "true", "false", "exit", "return", "sleep", "date", "which", "type", "wait",
            ":", "break", "continue"}
KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "{", "}", "time",
            "case", "esac", "in", "function", "[[", "]]", "nohup", "exec", "env", "command", "builtin",
            "sudo", "xargs", "timeout", "nice"}
ASSIGNERS = {"export", "local", "declare", "readonly", "typeset"}
HOME_TOOLCHAIN = ["go", ".cargo", ".rustup", ".cache/go-build", ".cache/zig", ".cache/cargo-zigbuild",
                  "Library/Caches/go-build", "Library/Caches/zig", "Library/Caches/cargo-zigbuild",
                  ".docker", ".config/go"]
SYS_ALLOW = ["/usr", "/bin", "/sbin", "/opt/homebrew", "/Library/Developer", "/Applications/Xcode.app",
             "/Applications/Docker.app", "/System", "/dev", "/var/folders"]


# ---------------------------------------------------------------------------------------------- paths

def fold(p):
    """Comparison form: normalized, /private aliases folded, lower case."""
    p = posixpath.normpath(p) if p else p
    if p.startswith("//"):
        p = "/" + p.lstrip("/")
    for pre in ("/private/tmp", "/private/var", "/private/etc"):
        if p == pre or p.startswith(pre + "/"):
            p = p[len("/private"):]
    return p.lower()


def under(p, root):
    return p == root or p.startswith(root.rstrip("/") + "/")


class Policy:
    def __init__(self, repo, ws, prefixes, others, scratch):
        self.repo = fold(repo)
        self.ws = fold(ws)
        self.ws_raw = [ws.rstrip("/")]
        for a, b in (("/private/tmp/", "/tmp/"), ("/tmp/", "/private/tmp/"),
                     ("/private/var/", "/var/"), ("/var/", "/private/var/")):
            if ws.startswith(a):
                self.ws_raw.append(b + ws[len(a):].rstrip("/"))
        self.ws_parent = posixpath.dirname(self.ws)
        self.hidden_parent = fold(str(HERE.parent))
        self.prefixes = [fold(x) if x.startswith("/") else x.lower() for x in prefixes]
        self.others = [fold(x) for x in others]
        self.allow = [self.ws] + [fold(s) for s in scratch] + [fold(x) for x in SYS_ALLOW] \
            + [fold(HOME + "/" + x) for x in HOME_TOOLCHAIN]
        self.markers = []
        for cat, subs in (
                ("hidden", [str(HERE), str(HERE.parent), "r4-hidden", "heimdall-m00", "r4-scratch",
                            "seeded-trees"]),
                ("round4-scratch", ["/tmp/hm-r4", "hm-r4"]),
                ("repository", [repo, "gitrepos/heimdall"]),
                ("task-pack", ["taskpack", "g02-r4/x2"]),
                ("other-workspace", list(others) + [p for p in prefixes])):
            for s in subs:
                for v in {s.lower(), fold(s)} if s.startswith("/") else {s.lower()}:
                    if v and v != "/":
                        self.markers.append((cat, v))
        par = posixpath.dirname(ws.rstrip("/"))
        forms = set()
        for w in [par] + [posixpath.dirname(x) for x in self.ws_raw]:
            forms |= {w.lower(), fold(w)}
        self.own_forms = sorted((f for f in forms if f and f != "/"), key=len, reverse=True)
        # A form counts only as a whole path element: /tmp/x2ws-ab must not swallow /tmp/x2ws-ab0.
        self.own_rx = re.compile("|".join(re.escape(f) + r"(?![A-Za-z0-9_.\-])" for f in self.own_forms)) \
            if self.own_forms else None

    def strip_own(self, low):
        """Remove the own workspace and its parent (all alias and case forms) from lower-cased text."""
        return self.own_rx.sub("\x01", low) if self.own_rx else low

    def marker_hits(self, text):
        """Categories of markers in text, after the own workspace (and its parent) is removed."""
        low = text.lower()
        if "\\" in low:
            low = low + "\n" + low.replace("\\/", "/").replace("\\u002f", "/")
        low = self.strip_own(low)
        return {cat for cat, m in self.markers if m in low}

    def klass(self, p):
        if under(p, self.repo):
            return "repository"
        if under(p, self.hidden_parent):
            return "hidden"
        if any(under(p, o) for o in self.others) or any(
                p.startswith(x) and not under(p, self.ws) and p != self.ws_parent for x in self.prefixes):
            return "other-workspace"
        if under(p, "/tmp"):
            return "tmp"
        if HOME and under(p, fold(HOME)):
            return "home"
        if p == "/":
            return "root"
        return "outside"

    def check(self, p):
        """p: absolute path, glob characters as sentinels.  Returns None (allowed) or a reason."""
        comps = p.split("/")
        k = next((i for i, c in enumerate(comps) if any(ch in SENTS for ch in c)), None)
        glob = k is not None
        static = "/".join(comps[:k]) if glob else p
        static = static or "/"
        escaping = False
        if glob:
            for c in comps[k:]:
                g = any(ch in SENTS for ch in c)
                # A later `..`, or a glob component that can match `..` (leading dot, bracket), leaves
                # the static prefix; `*` and `?` never match a leading dot.
                if ".." in c or (g and (c.startswith(".") or c.startswith(SENT["["]))):
                    escaping = True
        t = fold(static)
        if not under(t, self.ws):
            mk = self.marker_hits(t) | self.marker_hits(fold(p))
            if mk:
                return "marker:" + sorted(mk)[0]
        ok = any(under(t, a) for a in self.allow) or (not glob and t == self.ws_parent)
        if glob and escaping:
            ok = False
        if ok:
            return None
        return ("glob-outside:" if glob else "path-outside:") + self.klass(t)


# ---------------------------------------------------------------------------------------------- lexer

class LexError(Exception):
    pass


OPS = ["&&", "||", ";;", "<<<", "<<-", "<<", ">>", ">&", "<&", "&>", "|&", ">|", ";", "&", "|", "(", ")",
       "<", ">"]
OPCH = set(";&|()<>\n")


HEREDOC = re.compile(r"""<<(-?)[ \t]*(?:'([^'\n]*)'|"([^"\n]*)"|\\?([A-Za-z0-9_.-]+))""")


def _skip_heredoc(s, i):
    """s[i:] starts with a here-document operator (not <<<): index after its body, or None."""
    m = HEREDOC.match(s, i)
    if not m:
        return None
    delim = next(g for g in m.groups()[1:] if g is not None)
    j = s.find("\n", m.end())
    if j < 0:
        return len(s)
    k = j + 1
    while k <= len(s):
        e = s.find("\n", k)
        line = s[k:] if e < 0 else s[k:e]
        if (line.lstrip("\t") if m.group(1) else line) == delim:
            # The scan resumes at the newline ending the delimiter line once the operator's own line
            # is done (e.g. `$(cat <<'EOF'\n...\nEOF\n)` closes the substitution after the body).
            return len(s) if e < 0 else e
        if e < 0:
            break
        k = e + 1
    raise LexError("heredoc")


def _match(s, i, open_, close):
    """Index just past the bracket matching s[i-1] == open_ (quotes and here-documents respected)."""
    depth, n = 1, len(s)
    pend = None          # end of the body of a here-document whose operator is on the current line
    while i < n:
        c = s[i]
        if c == "\n" and pend is not None:
            i, pend = pend, None
            continue
        if c == "<" and s.startswith("<<", i) and not s.startswith("<<<", i):
            r = _skip_heredoc(s, i)
            if r is not None:
                pend = r
                i = HEREDOC.match(s, i).end()
                continue
        if c == "\\":
            i += 2
            continue
        if c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                raise LexError("quote")
            i = j + 1
            continue
        if c == '"':
            i = _dq_end(s, i + 1)
            continue
        if c == open_:
            depth += 1
        elif c == close:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise LexError("bracket")


def _dq_end(s, i):
    n = len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return i + 1
        if c == "$" and i + 1 < n and s[i + 1] == "(":
            i = _match(s, i + 2, "(", ")")
            continue
        if c == "`":
            j = s.find("`", i + 1)
            if j < 0:
                raise LexError("backtick")
            i = j + 1
            continue
        i += 1
    raise LexError("dquote")


def _dollar(s, i, pieces):
    """s[i] == '$'.  Appends a piece, returns the new index."""
    n = len(s)
    if i + 1 >= n:
        pieces.append(("lit", "$"))
        return i + 1
    c = s[i + 1]
    if s.startswith("$((", i):
        j = _match(s, i + 3, "(", ")")
        if j < n and s[j] == ")":
            j += 1
        pieces.append(("lit", "0"))
        return j
    if c == "(":
        j = _match(s, i + 2, "(", ")")
        pieces.append(("cmd", s[i + 2:j - 1]))
        return j
    if c == "{":
        j = _match(s, i + 2, "{", "}")
        inner = s[i + 2:j - 1]
        m = re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", inner)
        pieces.append(("var", inner if m else None))
        return j
    if c == "'":
        j = s.find("'", i + 2)
        if j < 0:
            raise LexError("quote")
        pieces.append(("lit", s[i + 2:j]))
        return j + 1
    if c in "?#$!-":
        pieces.append(("lit", "0"))
        return i + 2
    if c.isdigit() or c in "@*":
        pieces.append(("var", None))
        return i + 2
    m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", s[i + 1:])
    if m:
        pieces.append(("var", m.group(0)))
        return i + 1 + m.end()
    pieces.append(("lit", "$"))
    return i + 1


def _word(s, i):
    """Read one word starting at s[i].  Returns (pieces, raw, new index)."""
    start, n, pieces = i, len(s), []
    first = True
    while i < n:
        c = s[i]
        if c in " \t\r" or c in OPCH:
            break
        if c == "\\":
            if i + 1 < n and s[i + 1] == "\n":
                i += 2
                continue
            pieces.append(("lit", s[i + 1:i + 2]))
            i += 2
        elif c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                raise LexError("quote")
            pieces.append(("lit", s[i + 1:j]))
            i = j + 1
        elif c == '"':
            j = _dq_end(s, i + 1)
            k = i + 1
            while k < j - 1:
                d = s[k]
                if d == "\\" and k + 1 < j - 1 and s[k + 1] in '$`"\\':
                    pieces.append(("lit", s[k + 1]))
                    k += 2
                elif d == "$":
                    k = _dollar(s[:j - 1], k, pieces)
                elif d == "`":
                    e = s.find("`", k + 1)
                    pieces.append(("cmd", s[k + 1:e]))
                    k = e + 1
                else:
                    pieces.append(("lit", d))
                    k += 1
            i = j
        elif c == "$":
            i = _dollar(s, i, pieces)
        elif c == "`":
            j = s.find("`", i + 1)
            if j < 0:
                raise LexError("backtick")
            pieces.append(("cmd", s[i + 1:j]))
            i = j + 1
        elif c == "~" and first:
            m = re.match(r"~([A-Za-z0-9_.-]*)", s[i:])
            pieces.append(("tilde", m.group(1)))
            i += m.end()
        elif c in SENT:
            if c == "{" and s.startswith("{}", i):    # find -exec ... {} is a literal
                pieces.append(("lit", "{}"))
                i += 2
            else:
                pieces.append(("glob", SENT[c]))
                i += 1
        else:
            pieces.append(("lit", c))
            if c in "=:" and i + 1 < n and s[i + 1] == "~":   # assignment / PATH-list tilde
                m = re.match(r"~([A-Za-z0-9_.-]*)", s[i + 1:])
                pieces.append(("tilde", m.group(1)))
                i += 1 + m.end()
                continue
            i += 1
        first = False
    return pieces, s[start:i], i


def lex(s):
    """Items: ("word", pieces, raw) | ("op", op)."""
    items, i, n, pending = [], 0, len(s), []
    while i < n:
        c = s[i]
        if c in " \t\r":
            i += 1
            continue
        if c == "\\" and s.startswith("\\\n", i):
            i += 2
            continue
        if c == "#":
            j = s.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "\n":
            items.append(("op", "\n"))
            i += 1
            for delim, strip in pending:
                while i < n:
                    j = s.find("\n", i)
                    line = s[i:] if j < 0 else s[i:j]
                    i = n if j < 0 else j + 1
                    if (line.lstrip("\t") if strip else line) == delim:
                        break
            pending = []
            continue
        op = next((o for o in OPS if s.startswith(o, i)), None)
        if op:
            items.append(("op", op))
            i += len(op)
            if op in ("<<", "<<-"):
                while i < n and s[i] in " \t":
                    i += 1
                pieces, raw, i = _word(s, i)
                pending.append(("".join(v for k, v in pieces if k in ("lit",)) or raw, op == "<<-"))
            continue
        pieces, raw, i = _word(s, i)
        items.append(("word", pieces, raw))
    return items


# ------------------------------------------------------------------------------------- bash analysis

class Bash:
    def __init__(self, pol):
        self.pol = pol

    def expand(self, pieces, cwds, env):
        """List of possible strings (globs as sentinels), or None if an expansion is unknown."""
        outs = [""]
        for kind, v in pieces:
            if kind == "lit" or kind == "glob":
                vals = [v]
            elif kind == "tilde":
                if v:
                    return None
                vals = [HOME]
            elif kind == "var":
                if v is None:
                    return None
                if v in env:
                    vals = env[v]
                    if vals is None:
                        return None
                elif v == "HOME":
                    vals = [HOME]
                elif v == "PWD":
                    if any(c == UNK for c in cwds):
                        return None
                    vals = sorted(cwds)
                else:
                    return None
            else:   # command substitution: output unknown
                return None
            outs = [o + x for o in outs for x in vals][:64]
        return outs

    def candidates(self, s):
        if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", s):
            return []
        if s.startswith("-"):
            if "=" in s:
                return [s.split("=", 1)[1]] if s.split("=", 1)[1] else []
            m = re.match(r"^-+[A-Za-z0-9]*?([~/.%s].*)$" % "".join(SENTS), s)
            return [m.group(1)] if m else []
        m = re.match(r"^[A-Za-z_][A-Za-z0-9_]*=(.*)$", s)
        if m:
            return [x for x in m.group(1).split(":") if x]
        out = [s]
        if ":" in s:
            out += [x for x in s.split(":")[1:] if x[:1] in ("/", "~", ".")]
        return out

    def check_word(self, pieces, raw, cwds, env, reasons):
        vals = self.expand(pieces, cwds, env)
        if vals is None:
            reasons.add("unresolved-expansion")
            return
        for s in vals:
            for c in self.candidates(s):
                if c.startswith("~"):
                    c = HOME + c[1:] if c == "~" or c.startswith("~/") else c
                if c.startswith("/"):
                    r = self.pol.check(c)
                    if r:
                        reasons.add(r)
                    continue
                for cwd in cwds:
                    if cwd == UNK:
                        reasons.add("cwd-unknown")
                        continue
                    r = self.pol.check(posixpath.join(cwd, c))
                    if r:
                        reasons.add(r)

    def analyze(self, text, cwds, reasons, depth=0):
        """Walk one command text; returns every cwd set seen (for the raw ../ scan)."""
        try:
            items = lex(text)
        except (LexError, IndexError, AttributeError):
            reasons.add("unparsed-command")
            return [set(cwds)]
        env = {}
        seen = [set(cwds)]
        stack = []
        state = {"C": set(cwds), "prev": None}
        words, redirs = [], []

        def finish(sep):
            if words or redirs:
                self.simple(words, redirs, state, env, reasons, sep, depth)
                seen.append(set(state["C"]))
            words.clear()
            redirs.clear()
            state["prev"] = sep

        expect = None    # "redir" | "heredoc-delim"
        for it in items:
            if it[0] == "op":
                op = it[1]
                if op in ("<", ">", ">>", ">|", "&>", "<<<"):
                    expect = "redir" if op != "<<<" else "herestring"
                    continue
                if op in (">&", "<&"):
                    expect = "fd"
                    continue
                if op in ("<<", "<<-"):
                    continue          # lex() consumed the delimiter and the body
                if op == "(":
                    if not words:
                        stack.append(set(state["C"]))
                    continue
                if op == ")":
                    finish(")")
                    if stack:
                        state["C"] = stack.pop()
                    continue
                finish(op)
                continue
            _, pieces, raw = it
            if expect == "redir":
                redirs.append((pieces, raw))
            elif expect == "fd":
                if not re.fullmatch(r"[0-9-]+", raw):
                    redirs.append((pieces, raw))
            elif expect in ("herestring", "skip"):
                pass
            else:
                words.append((pieces, raw))
            expect = None
            for kind, v in pieces:
                if kind == "cmd" and depth < 4:
                    seen.extend(self.analyze(v, state["C"], reasons, depth + 1))
        finish(None)
        return seen

    def simple(self, words, redirs, state, env, reasons, sep, depth):
        C = state["C"]
        for pieces, raw in redirs:
            self.check_word(pieces, raw, C, env, reasons)
        ws = list(words)
        # leading assignments
        while ws and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", ws[0][1]):
            pieces, raw = ws.pop(0)
            name = raw.split("=", 1)[0]
            vals = self.expand(pieces, C, env)
            if vals is not None:          # an unknown value is flagged where the variable is used
                self.check_word(pieces, raw, C, env, reasons)
            if not ws:
                env[name] = None if vals is None else [v.split("=", 1)[1] for v in vals]
        while ws and ws[0][1] in KEYWORDS:
            ws.pop(0)
        if not ws:
            return
        name_vals = self.expand(ws[0][0], C, env)
        name = posixpath.basename(name_vals[0]) if name_vals else None
        if name == "for" and len(ws) >= 2:
            var = ws[1][1]
            items = ws[3:] if len(ws) > 2 and ws[2][1] == "in" else []
            vals = []
            for pieces, raw in items:
                self.check_word(pieces, raw, C, env, reasons)
                v = self.expand(pieces, C, env)
                if v is None:
                    vals = None
                    break
                vals.extend(v)
            env[var] = vals
            return
        if name in ("cd", "pushd", "popd"):
            args = [w for w in ws[1:] if not w[1].startswith("-") or w[1] == "-"]
            if name == "popd" or (args and args[0][1] == "-"):
                new = {UNK}
            else:
                if args:
                    self.check_word(args[0][0], args[0][1], C, env, reasons)
                    tv = self.expand(args[0][0], C, env)
                else:
                    tv = [HOME]
                    r = self.pol.check(HOME)
                    if r:
                        reasons.add(r)
                new = set()
                for c in C:
                    if tv is None or c == UNK:
                        new.add(UNK)
                        continue
                    for t in tv:
                        if any(ch in SENTS for ch in t):
                            new.add(UNK)
                        else:
                            t = HOME + t[1:] if t == "~" or t.startswith("~/") else t
                            new.add(posixpath.normpath(posixpath.join(c, t)))
            loose = state["prev"] in ("|", "|&", "&") or sep in ("|", "|&", "&", "||")
            state["C"] = (C | new) if loose else new
            return
        if name in ASSIGNERS:
            for pieces, raw in ws[1:]:
                if raw.startswith("-"):
                    continue
                m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", raw)
                vals = self.expand(pieces, C, env)
                if vals is not None or not m:
                    self.check_word(pieces, raw, C, env, reasons)
                if m:
                    env[m.group(1)] = None if vals is None else [v.split("=", 1)[1] for v in vals]
            return
        if name in HARMLESS:
            return
        for c in C:
            if c == UNK:
                reasons.add("cwd-unknown")
            else:
                r = self.pol.check(c)
                if r:
                    reasons.add("cwd-outside:" + r.split(":", 1)[1])
        first = ws[0]
        if name_vals is None or "/" in "".join(name_vals):
            self.check_word(first[0], first[1], C, env, reasons)
        for pieces, raw in ws[1:]:
            self.check_word(pieces, raw, C, env, reasons)


RAW_ABS = re.compile(r"""(?:^|(?<=[\s'"`=:(,\[{<>|;&]))((?:\$\{HOME\}|\$HOME|~)(?=/|$|[\s'"`;|&()<>,])"""
                     r"""(?:/[^\s'"`;|&()<>,]*)?|/[^\s'"`;|&()<>,]*)""")
RAW_REL = re.compile(r"""(?:^|(?<=[\s'"`=:(,]))(\.\.(?:/[^\s'"`;|&()<>,]*)?)(?=$|[\s'"`;|&()<>,])""")
URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://\S*")


def closing_quotes(text):
    """Positions of shell-level closing quotes (a `/` right after one continues a shell word that the
    tokenizer already resolved, e.g. "$X"/internal; quotes inside another quoting are not counted)."""
    out, i, n, q = set(), 0, len(text), None
    while i < n:
        c = text[i]
        if c == "\\" and q != "'":
            i += 2
            continue
        if q is None and c in "'\"":
            q = c
        elif q is not None and c == q:
            out.add(i)
            q = None
        i += 1
    return out


def raw_scan(pol, text, cwd_sets, reasons):
    """Paths embedded anywhere in the text (heredocs, -c code, backticks)."""
    text = URL.sub(" ", text)
    closing = closing_quotes(text)
    for m in RAW_ABS.finditer(text):
        if m.start() - 1 in closing and m.group(1).startswith("/"):
            continue
        p = m.group(1)
        if p.startswith("${HOME}"):
            p = HOME + p[len("${HOME}"):]
        elif p.startswith("$HOME"):
            p = HOME + p[len("$HOME"):]
        elif p.startswith("~"):
            p = HOME + p[1:]
        if not p.strip("/"):
            before = text[m.start() - 1:m.start()] if m.start() else ""
            if p != "/" or before not in ("'", '"'):
                continue
        p = "".join(SENT.get(ch, ch) for ch in p)
        r = pol.check(p)
        if r:
            reasons.add("raw-" + r if not r.startswith("marker") else r)
    for m in RAW_REL.finditer(text):
        rel = "".join(SENT.get(ch, ch) for ch in m.group(1))
        cwds = set().union(*cwd_sets) if cwd_sets else {UNK}
        results = []
        for c in cwds:
            results.append(None if c == UNK else pol.check(posixpath.join(c, rel)))
        if results and all(r is not None for r in results) or UNK in cwds:
            bad = [r for r in results if r] or ["cwd-unknown"]
            reasons.add("raw-" + bad[0] if not bad[0].startswith("marker") else bad[0])


# ------------------------------------------------------------------------------------ tool analysis

PATH_TOOLS = {"Read": ["file_path"], "Write": ["file_path"], "Edit": ["file_path"], "MultiEdit": ["file_path"],
              "NotebookEdit": ["notebook_path"], "NotebookRead": ["notebook_path"], "LS": ["path"]}
SKIP_TOOLS = {"TodoWrite", "Task", "Agent", "WebFetch", "WebSearch", "BashOutput", "KillShell", "KillBash",
              "ExitPlanMode", "Skill", "StructuredOutput"}


def strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield k
            yield from strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from strings(v)


def resolve_one(pol, p, cwd, reasons, globby=False):
    if not isinstance(p, str) or not p:
        return
    if globby:
        p = "".join(SENT.get(ch, ch) for ch in p)
    if p.startswith("~"):
        p = HOME + p[1:]
    if not p.startswith("/"):
        if cwd == UNK:
            reasons.add("cwd-unknown")
            return
        p = posixpath.join(cwd, p)
    r = pol.check(p)
    if r:
        reasons.add(r)


def tool_call(pol, name, inp, cwd):
    reasons = set()
    inp = inp if isinstance(inp, dict) else {}
    alltext = "\n".join(strings(inp))
    if name not in SKIP_TOOLS:
        for cat in pol.marker_hits(alltext):
            reasons.add("marker:" + cat)
    if name == "Bash":
        cmd = inp.get("command") or ""
        seen = Bash(pol).analyze(cmd, {cwd}, reasons)
        raw_scan(pol, cmd, seen, reasons)
    elif name in PATH_TOOLS:
        for key in PATH_TOOLS[name]:
            resolve_one(pol, inp.get(key), cwd, reasons)
    elif name in ("Glob", "Grep"):
        base = inp.get("path") or cwd
        resolve_one(pol, base, cwd, reasons)
        if not isinstance(base, str):
            base = cwd
        if base != UNK and not base.startswith("/"):
            base = posixpath.join(cwd, base) if cwd != UNK else UNK
        pat = inp.get("pattern") if name == "Glob" else inp.get("glob")
        if isinstance(pat, str) and pat:
            if pat.startswith("/") or pat.startswith("~"):
                resolve_one(pol, pat, cwd, reasons, globby=True)
            elif base != UNK:
                resolve_one(pol, posixpath.join(base, pat), cwd, reasons, globby=True)
            else:
                reasons.add("cwd-unknown")
    elif name not in SKIP_TOOLS:
        raw_scan(pol, alltext, [{cwd}], reasons)
    return reasons


def transcripts(args):
    seen = set()
    for a in args:
        p = Path(a)
        if p.is_dir():
            files = set(p.rglob("*.jsonl")) | {q for q in p.rglob("*.txt") if "tool-results" in q.parts}
            for q in sorted(files):
                if q.resolve() not in seen:
                    seen.add(q.resolve())
                    yield q, "%s/%s" % (p.name, q.relative_to(p))
        elif p.is_file():
            if p.resolve() not in seen:
                seen.add(p.resolve())
                yield p, p.name
        else:
            raise FileNotFoundError(p.name)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repo", required=True, help="the heimdall repository root")
    ap.add_argument("--workspace", required=True, help="the implementer's own workspace root")
    ap.add_argument("--workspace-prefix", action="append", default=[],
                    help="common prefix of all X2 workspaces, e.g. /tmp/x2ws- (repeatable)")
    ap.add_argument("--other-workspace", action="append", default=[], help="another cell's workspace (repeatable)")
    ap.add_argument("--scratch", action="append", default=[],
                    help="another place the implementer may use (repeatable), e.g. its own session directory")
    ap.add_argument("--json", action="store_true", help="print one JSON object instead of lines")
    ap.add_argument("transcripts", nargs="+")
    a = ap.parse_args()
    repo = str(Path(a.repo).resolve())
    ws = a.workspace.rstrip("/")
    if not ws.startswith("/"):
        print("audit: --workspace must be absolute", file=sys.stderr)
        return 2
    if under(fold(ws), fold(repo)) or under(fold(ws), fold(str(HERE.parent))):
        print("audit: the workspace lies inside the repository or the hidden material; rebuild it", file=sys.stderr)
        return 2
    pol = Policy(repo, ws, a.workspace_prefix, a.other_workspace, a.scratch)
    try:
        files = list(transcripts(a.transcripts))
    except FileNotFoundError as e:
        print("audit: not a file or directory: %s" % e, file=sys.stderr)
        return 2
    if not files:
        print("audit: no .jsonl transcripts found", file=sys.stderr)
        return 2
    calls, entries, notes = [], [], []
    ncalls = 0
    for p, shown in files:
        by_id = {}
        cwd = None
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                if p.suffix == ".txt":
                    mk = pol.marker_hits(line)
                    if mk:
                        entries.append({"file": shown, "line": n, "reasons": ["output-marker:" + c for c in sorted(mk)]})
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    mk = pol.marker_hits(line)
                    if mk:
                        entries.append({"file": shown, "line": n, "reasons": ["marker:" + c for c in sorted(mk)]})
                    continue
                if not isinstance(e, dict):
                    continue
                if isinstance(e.get("cwd"), str) and e["cwd"].startswith("/"):
                    cwd = e["cwd"]
                role = e.get("type")
                msg = e.get("message") if isinstance(e.get("message"), dict) else {}
                content = msg.get("content")
                blocks = content if isinstance(content, list) else []
                attributed = False
                for b in blocks:
                    if not isinstance(b, dict):
                        continue
                    t = b.get("type")
                    if t == "tool_use":
                        ncalls += 1
                        idx = ncalls
                        r = tool_call(pol, str(b.get("name")), b.get("input"), cwd or UNK)
                        rec = {"index": idx, "file": shown, "line": n, "tool": str(b.get("name"))[:64],
                               "reasons": set(r)}
                        by_id[b.get("id")] = rec
                        calls.append(rec)
                    elif t == "tool_result":
                        mk = pol.marker_hits("\n".join(strings(b.get("content"))))
                        tur = e.get("toolUseResult")
                        if tur is not None:
                            mk |= pol.marker_hits("\n".join(strings(tur)))
                        attributed = True
                        if mk:
                            rec = by_id.get(b.get("tool_use_id"))
                            if rec is not None:
                                rec["reasons"] |= {"output-marker:" + c for c in mk}
                            else:
                                entries.append({"file": shown, "line": n,
                                                "reasons": ["output-marker:" + c for c in sorted(mk)]})
                    elif t in ("text", "thinking", "redacted_thinking"):
                        mk = pol.marker_hits("\n".join(strings(b)))
                        if mk:
                            notes.append({"file": shown, "line": n, "place": "assistant" if role == "assistant" else "prompt",
                                          "reasons": ["marker:" + c for c in sorted(mk)]})
                if isinstance(content, str):
                    mk = pol.marker_hits(content)
                    if mk:
                        notes.append({"file": shown, "line": n, "place": "assistant" if role == "assistant" else "prompt",
                                      "reasons": ["marker:" + c for c in sorted(mk)]})
                if not attributed and e.get("toolUseResult") is not None:
                    mk = pol.marker_hits("\n".join(strings(e.get("toolUseResult"))))
                    if mk:
                        entries.append({"file": shown, "line": n, "reasons": ["output-marker:" + c for c in sorted(mk)]})
                if e.get("attachment") is not None:
                    mk = pol.marker_hits("\n".join(strings(e.get("attachment"))))
                    if mk:
                        notes.append({"file": shown, "line": n, "place": "prompt",
                                      "reasons": ["marker:" + c for c in sorted(mk)]})
    bad = [c for c in calls if c["reasons"]]
    verdict = "SUSPECT" if bad or entries else "CLEAN"
    if a.json:
        print(json.dumps({"verdict": verdict, "transcript_files": len(files), "tool_calls": ncalls,
                          "offending_calls": [dict(c, reasons=sorted(c["reasons"])) for c in bad],
                          "entries": entries, "notes": notes}, indent=1))
    else:
        for c in bad:
            print("CALL %d %s line %d %s: %s" % (c["index"], c["file"], c["line"], c["tool"], ",".join(sorted(c["reasons"]))))
        for x in entries:
            print("ENTRY %s line %d: %s" % (x["file"], x["line"], ",".join(x["reasons"])))
        for x in notes:
            print("NOTE %s line %d %s: %s" % (x["file"], x["line"], x["place"], ",".join(x["reasons"])))
        if verdict == "CLEAN":
            print("VERDICT CLEAN")
        else:
            print("VERDICT SUSPECT calls %s entries %d" % ([c["index"] for c in bad], len(entries)))
        print("audit: %d transcript file(s), %d tool call(s), %d offending" % (len(files), ncalls, len(bad)))
    return 1 if verdict == "SUSPECT" else 0


if __name__ == "__main__":
    sys.exit(main())
