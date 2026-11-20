#!/usr/bin/env python3
"""Claim-table check (ADR-0008 D12 item 3; m03-plan U0, section 5 item 16).

Usage (stdlib only; from anywhere):

    python3 -I tools/validation/claims_table.py               # the real table, then the self-tests
    python3 -I tools/validation/claims_table.py --self-test   # the self-tests only

Exit code: 0 only when every check passes; 1 otherwise.

It parses `pub const CLAIMS: &[Claim] = &[ ... ];` from `crates/domain/src/claims.rs`
(comments and whitespace are tolerated; string literals only). Each entry is one
`Claim { field, value, platform: Platform { os, arch }, os_floor,
client_versions: VersionRange { min, max }, signer_builds: VersionRange { min, max },
build_profile: BuildProfile::Release | BuildProfile::Debug, store_kind: Some("..") | None,
record, record_commit }` literal. An entry that cannot be parsed (unknown or missing or
duplicated field, wrong literal kind) is a failure; it is never skipped.

For every entry (D12 item 3):
  * `record` is a normalized repository-relative path, and the record is read **at its cited
    revision**: `git -C <repo> show <record_commit>:<record>` (never the working tree). A record
    absent at that revision, or one that does not parse, fails the entry. Every record check
    below runs on that revision's content;
  * the record validates against
    `tests/evidence/record.schema.json` (tests/g02/minischema.py, as validate-records.py);
  * the record's status is `verified` **for that platform row**: the record's
    `observed_result.rows` (a list, or a mapping keyed by platform) is searched for rows
    naming the entry's `platform.os` and `platform.arch` (a row's `platform` string such as
    `macos-arm64 (build host)` or `windows-11-x86_64`, or its `os` and `arch` keys). At
    least one row must match and **every** matching row must be `verified`; a record with no
    row for the platform fails. (The record's own top-level status is the lowest of all its
    rows, so a `blocked` record that has a verified row for this platform is accepted only
    through that row, as the evidence README says.)
  * `record_commit` is a commit that is an ancestor of HEAD
    (`git merge-base --is-ancestor <commit> HEAD`);
  * ⟨M03-F1-R06⟩ the version bounds equal the record's normalized host facts at that revision
    (`environment.host_facts.<platform.os>`), exactly:
      - `os_floor` == the OS release of `os` (macOS ProductVersion, the Linux kernel release,
        the Windows version number);
      - `client_versions.min` and `.max` == the OpenSSH client version (`ssh-V`; on Windows
        `ssh-V-inbox`, the in-box client the harness selects; never `ssh-V-path-first`);
      - `signer_builds.min` and `.max` == the `[workspace.package]` `version` of `Cargo.toml` at
        the same revision (signer builds are pinned identities, so min != max fails).
    A missing fact, a value that does not normalize (the version token must be complete) or a
    mismatch fails the entry, naming the bound and the record's value;
  * for custody-dependent fields (`CUSTODY_FIELDS`, read from the same file): the build
    profile is `Release` and `store_kind` is one of the platform's product store kinds
    (`product_store_kinds(os)`, read from the same file and checked against the mirror
    below; the two must agree). Test-store evidence never satisfies a product-store claim.

⟨ADR-0008 §17.33 item 7⟩ It also parses `pub const RESIDUALS: &[Residual] = &[ ... ];`, the
named residuals: each `Residual { id, description, platform: Platform { os, arch }, limits,
probe: Probe { target, source, test }, reason: ResidualReason::FailClosedOnly |
ResidualReason::NeedsHostileSameUserProgram, adr }`. A residual is never a verified claim: an
entry carrying a claim's fields (`value`, `status`, `record`, `record_commit`, `verified`) is a
violation, and so is one whose `id` is a CLAIMS `field`, a duplicate or malformed `id`, an
unknown platform (`any` is allowed for residuals), or a probe whose `source` is missing,
outside the repository, or does not define the named test (`fn <name>(` after a `#[test]` or
`#[tokio::test]` attribute, with or without arguments). Where no test is feasible an entry cites
code instead: an empty `test` and a `target` starting with `code:` (its `source` must exist).

The empty table passes (the M03 baseline). Self-tests, each printed with PASS or FAIL,
build fixture tables and records in a `tempfile.mkdtemp()` directory removed afterwards:
  claims_table_empty_validates
  claims_table_rejects_entry_for_blocked_record
  claims_table_rejects_debug_profile_or_test_store_for_custody_claim
  claims_table_positive_control (a valid fixture entry passes; a parse error fails)
  claims_table_rejects_residual_marked_verified
  claims_table_rejects_residual_presented_as_claim
  claims_table_rejects_residual_without_its_test
  claims_table_residual_positive_control
  claims_table_residual_tokio_test_with_args_and_code_citation
  claims_table_rejects_bounds_unrelated_to_the_record
  claims_table_reads_the_record_at_its_cited_revision
  claims_table_host_fact_normalizers_are_strict
  claims_table_rejects_a_cited_record_that_is_not_an_object
"""
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "tests", "g02"))
import minischema  # noqa: E402

CLAIMS_RS = os.path.join(ROOT, "crates", "domain", "src", "claims.rs")
SCHEMA = os.path.join(ROOT, "tests", "evidence", "record.schema.json")

# Mirror of claims.rs `product_store_kinds`; the file's own copy must agree with it.
MIRROR_PRODUCT_STORE_KINDS = {
    "macos": ["macos_login_keychain", "macos_data_protection_keychain"],
    "windows": ["windows_dpapi"],
    "linux": ["linux_secret_service"],
}
MIRROR_CUSTODY_FIELDS = ["lock_continuity"]
# Never a product store, whatever the Rust table says.
TEST_STORE_KINDS = {"scratch", "scratch_test"}

OS_VALUES = {"macos", "linux", "windows"}
ARCH_VALUES = {"aarch64", "x86_64"}
ARCH_ALIASES = {
    "aarch64": ("aarch64", "arm64"),
    "x86_64": ("x86_64", "x64", "amd64"),
}


class ParseError(Exception):
    pass


# ---------------------------------------------------------------------------
# A small Rust-subset tokenizer: strings, idents, punctuation; comments dropped.

def tokenize(text):
    toks = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j + 1
        elif text.startswith("/*", i):
            depth, i = 1, i + 2
            while i < n and depth:
                if text.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif text.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            if depth:
                raise ParseError("unterminated block comment")
        elif c == '"':
            j, buf = i + 1, []
            while True:
                if j >= n:
                    raise ParseError("unterminated string literal")
                ch = text[j]
                if ch == "\\":
                    nxt = text[j + 1: j + 2]
                    if nxt in ('"', "\\"):
                        buf.append(nxt)
                        j += 2
                    else:
                        raise ParseError("unsupported escape in a string literal")
                elif ch == '"':
                    break
                else:
                    buf.append(ch)
                    j += 1
            toks.append(("str", "".join(buf)))
            i = j + 1
        elif c == "r" and re.match(r'r#*"', text[i:]):
            raise ParseError("raw string literals are not supported in the claim table")
        elif c.isalpha() or c == "_":
            m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", text[i:])
            toks.append(("id", m.group(0)))
            i += m.end()
        elif text.startswith("::", i):
            toks.append(("p", "::"))
            i += 2
        elif text.startswith("=>", i):
            toks.append(("p", "=>"))
            i += 2
        elif c in "{}()[],:;=&<>#!":
            toks.append(("p", c))
            i += 1
        elif c.isdigit():
            raise ParseError("numeric literal in the claim table (strings only)")
        else:
            raise ParseError("unexpected character %r" % c)
    return toks


class Cursor:
    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else ("eof", "")

    def take(self, kind=None, value=None):
        tok = self.peek()
        if tok[0] == "eof" or (kind and tok[0] != kind) or (value is not None and tok[1] != value):
            raise ParseError("expected %s but found %s" % (value or kind, tok[1] or "end of input"))
        self.i += 1
        return tok[1]

    def at(self, kind, value=None):
        tok = self.peek()
        return tok[0] == kind and (value is None or tok[1] == value)


def _struct(cur, name, schema):
    """Parse `name { field: <kind>, ... }` where schema maps field -> a parser."""
    cur.take("id", name)
    cur.take("p", "{")
    out = {}
    while not cur.at("p", "}"):
        field = cur.take("id")
        if field not in schema:
            raise ParseError("%s: unknown field `%s`" % (name, field))
        if field in out:
            raise ParseError("%s: duplicate field `%s`" % (name, field))
        cur.take("p", ":")
        out[field] = schema[field](cur)
        if cur.at("p", ","):
            cur.take("p", ",")
        elif not cur.at("p", "}"):
            raise ParseError("%s: expected `,` or `}` after field `%s`" % (name, field))
    cur.take("p", "}")
    missing = sorted(set(schema) - set(out))
    if missing:
        raise ParseError("%s: missing field(s) %s" % (name, ", ".join(missing)))
    return out


def _str(cur):
    return cur.take("str")


def _profile(cur):
    cur.take("id", "BuildProfile")
    cur.take("p", "::")
    v = cur.take("id")
    if v not in ("Release", "Debug"):
        raise ParseError("build_profile: expected Release or Debug, found %s" % v)
    return v


def _opt_str(cur):
    v = cur.take("id")
    if v == "None":
        return None
    if v == "Some":
        cur.take("p", "(")
        s = cur.take("str")
        cur.take("p", ")")
        return s
    raise ParseError("store_kind: expected Some(\"..\") or None, found %s" % v)


def _version_range(cur):
    return _struct(cur, "VersionRange", {"min": _str, "max": _str})


def _platform(cur):
    return _struct(cur, "Platform", {"os": _str, "arch": _str})


CLAIM_SCHEMA = {
    "field": _str,
    "value": _str,
    "platform": _platform,
    "os_floor": _str,
    "client_versions": _version_range,
    "signer_builds": _version_range,
    "build_profile": _profile,
    "store_kind": _opt_str,
    "record": _str,
    "record_commit": _str,
}


def strip_for_search(text):
    """The source with comments removed and string contents kept (for regex lookups)."""
    out, i, n = [], 0, len(text)
    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif text[i] == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i: j + 1])
            i = j + 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def _matching(text, start, open_ch, close_ch):
    """Index of the bracket that closes the one at text[start] (strings are skipped)."""
    depth, i, n = 0, start, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ParseError("unbalanced %s%s" % (open_ch, close_ch))


def parse_claims(source):
    """Return (entries, custody_fields, product_store_kinds) parsed from claims.rs source."""
    text = strip_for_search(source)
    matches = list(re.finditer(r"pub\s+const\s+CLAIMS\s*:\s*&\s*\[\s*Claim\s*\]\s*=\s*&\s*\[", text))
    if len(matches) != 1:
        raise ParseError("expected exactly one `pub const CLAIMS: &[Claim] = &[` (found %d)" % len(matches))
    start = matches[0].end() - 1
    end = _matching(text, start, "[", "]")
    if not re.match(r"\s*;", text[end + 1:]):
        raise ParseError("CLAIMS is not terminated by `;`")
    cur = Cursor(tokenize(text[start + 1: end]))
    entries = []
    while cur.peek()[0] != "eof":
        entries.append(_struct(cur, "Claim", CLAIM_SCHEMA))
        if cur.at("p", ","):
            cur.take("p", ",")
        elif cur.peek()[0] != "eof":
            raise ParseError("expected `,` between Claim entries, found %s" % cur.peek()[1])

    m = re.search(r"pub\s+const\s+CUSTODY_FIELDS\s*:\s*&\s*\[\s*&\s*str\s*\]\s*=\s*&\s*\[", text)
    if not m:
        raise ParseError("CUSTODY_FIELDS not found")
    s = m.end() - 1
    custody = re.findall(r'"([^"]*)"', text[s: _matching(text, s, "[", "]")])

    m = re.search(r"pub\s+fn\s+product_store_kinds\b[^{]*\{", text)
    if not m:
        raise ParseError("product_store_kinds not found")
    body = text[m.end() - 1: _matching(text, m.end() - 1, "{", "}")]
    kinds = {}
    for arm in re.finditer(r'"([a-z0-9_]+)"\s*=>\s*&\s*\[([^\]]*)\]', body):
        kinds[arm.group(1)] = re.findall(r'"([^"]*)"', arm.group(2))
    return entries, custody, kinds


# ---------------------------------------------------------------------------
# Residuals (ADR-0008 §17.33 item 7)

RESIDUAL_REASONS = {"FailClosedOnly", "NeedsHostileSameUserProgram"}
# Fields that would make a residual look like a verified claim.
CLAIM_LIKE_FIELDS = {"value", "status", "record", "record_commit", "verified", "field"}


def _reason(cur):
    cur.take("id", "ResidualReason")
    cur.take("p", "::")
    return cur.take("id")


def _probe(cur):
    return _struct(cur, "Probe", {"target": _str, "source": _str, "test": _str})


def _any_value(cur):
    """A claim-like field's value, whatever its literal (kept only to report it)."""
    if cur.at("str"):
        return cur.take("str")
    if cur.at("id"):
        v = cur.take("id")
        while cur.at("p", "::"):
            cur.take("p", "::")
            v += "::" + cur.take("id")
        return v
    raise ParseError("unsupported value of a claim-like field in a Residual")


RESIDUAL_SCHEMA = {
    "id": _str,
    "description": _str,
    "platform": _platform,
    "limits": _str,
    "probe": _probe,
    "reason": _reason,
    "adr": _str,
}


def _residual(cur):
    """`Residual { ... }`; claim-like fields are collected (and later refused), any other
    unknown field is a parse error."""
    cur.take("id", "Residual")
    cur.take("p", "{")
    out, claimish = {}, {}
    while not cur.at("p", "}"):
        field = cur.take("id")
        cur.take("p", ":")
        if field in CLAIM_LIKE_FIELDS:
            claimish[field] = _any_value(cur)
        elif field in RESIDUAL_SCHEMA:
            if field in out:
                raise ParseError("Residual: duplicate field `%s`" % field)
            out[field] = RESIDUAL_SCHEMA[field](cur)
        else:
            raise ParseError("Residual: unknown field `%s`" % field)
        if cur.at("p", ","):
            cur.take("p", ",")
        elif not cur.at("p", "}"):
            raise ParseError("Residual: expected `,` or `}` after field `%s`" % field)
    cur.take("p", "}")
    missing = sorted(set(RESIDUAL_SCHEMA) - set(out))
    if missing:
        raise ParseError("Residual: missing field(s) %s" % ", ".join(missing))
    out["claim_like"] = claimish
    return out


def parse_residuals(source):
    """The RESIDUALS entries of claims.rs source (none when the list is absent)."""
    text = strip_for_search(source)
    matches = list(re.finditer(r"pub\s+const\s+RESIDUALS\s*:\s*&\s*\[\s*Residual\s*\]\s*=\s*&\s*\[", text))
    if not matches:
        return []
    if len(matches) != 1:
        raise ParseError("expected at most one `pub const RESIDUALS: &[Residual] = &[`")
    start = matches[0].end() - 1
    end = _matching(text, start, "[", "]")
    if not re.match(r"\s*;", text[end + 1:]):
        raise ParseError("RESIDUALS is not terminated by `;`")
    cur = Cursor(tokenize(text[start + 1: end]))
    out = []
    while cur.peek()[0] != "eof":
        out.append(_residual(cur))
        if cur.at("p", ","):
            cur.take("p", ",")
        elif cur.peek()[0] != "eof":
            raise ParseError("expected `,` between Residual entries, found %s" % cur.peek()[1])
    return out


def _defines_test(path, name):
    with open(path, encoding="utf-8") as f:
        src = f.read()
    for m in re.finditer(r"\bfn\s+%s\s*\(" % re.escape(name), src):
        before = src[max(0, m.start() - 600): m.start()]
        if re.search(r"#\[(tokio::)?test(\([^\]]*\))?\]", before):
            return True
    return False


def check_residuals(residuals, claims, record_root):
    bad = []
    real_root = os.path.realpath(record_root)
    seen = set()
    claim_fields = {c["field"] for c in claims}
    for n, r in enumerate(residuals):
        rid = r["id"]
        tag = "residual %d (%s)" % (n, rid)
        if r["claim_like"]:
            bad.append(
                "%s: a residual is never a verified claim, but it carries %s"
                % (tag, ", ".join("%s=%r" % kv for kv in sorted(r["claim_like"].items())))
            )
        if not re.fullmatch(r"[a-z][a-z0-9_]*", rid or ""):
            bad.append("%s: id must be lowercase letters, digits and `_`" % tag)
        if rid in seen:
            bad.append("%s: duplicate id" % tag)
        seen.add(rid)
        if rid in claim_fields:
            bad.append("%s: its id is a CLAIMS field; a residual is never presented as a claim" % tag)
        osn, arch = r["platform"]["os"], r["platform"]["arch"]
        if osn not in OS_VALUES | {"any"}:
            bad.append("%s: unknown platform.os %r" % (tag, osn))
        if arch not in ARCH_VALUES | {"any"}:
            bad.append("%s: unknown platform.arch %r" % (tag, arch))
        if r["reason"] not in RESIDUAL_REASONS:
            bad.append("%s: reason %r is not one of %s" % (tag, r["reason"], ", ".join(sorted(RESIDUAL_REASONS))))
        for f in ("description", "limits", "adr"):
            if not r[f]:
                bad.append("%s: empty %s" % (tag, f))
        probe = r["probe"]
        src = probe["source"]
        path = os.path.realpath(os.path.join(real_root, src))
        name = probe["test"].rsplit("::", 1)[-1]
        if not src or os.path.isabs(src) or not path.startswith(real_root + os.sep):
            bad.append("%s: probe source %r is empty, absolute or outside the repository" % (tag, src))
        elif not os.path.isfile(path):
            bad.append("%s: probe source %s does not exist" % (tag, src))
        elif not probe["test"]:
            if not probe["target"].startswith("code:"):
                bad.append("%s: no test is named and no code is cited (`code:` target)" % tag)
        elif not name or not _defines_test(path, name):
            bad.append("%s: probe source %s does not define the test %s" % (tag, src, probe["test"]))
        if not probe["target"]:
            bad.append("%s: empty probe target" % tag)
    return bad


# ---------------------------------------------------------------------------
# Row matching

def _norm_os(s):
    s = (s or "").strip().lower()
    for os_name in OS_VALUES:
        if s == os_name or s.startswith(os_name + "-") or s.startswith(os_name + " ") or s.startswith(os_name + "_"):
            return os_name
    if s in ("darwin", "mac", "macosx"):
        return "macos"
    return None


def _norm_arch(s):
    s = (s or "").lower()
    for canon, aliases in ARCH_ALIASES.items():
        for a in aliases:
            if re.search(r"(?<![a-z0-9])%s(?![a-z0-9])" % re.escape(a), s):
                return canon
    return None


def row_platform(row):
    """(os, arch) a record row names, or (None, None)."""
    if not isinstance(row, dict):
        return None, None
    if isinstance(row.get("os"), str) and isinstance(row.get("arch"), str):
        return _norm_os(row["os"]), _norm_arch(row["arch"])
    p = row.get("platform")
    if isinstance(p, str):
        return _norm_os(p), _norm_arch(p)
    return None, None


def record_rows(record):
    obs = record.get("observed_result")
    if not isinstance(obs, dict):
        return []
    rows = obs.get("rows")
    if isinstance(rows, list):
        return [r for r in rows if isinstance(r, dict)]
    if isinstance(rows, dict):
        out = []
        for k, v in rows.items():
            if isinstance(v, dict):
                out.append(dict(v, platform=v.get("platform", k)))
        return out
    return []


# ---------------------------------------------------------------------------
# The check

def _first_word(value):
    """The first word of a recorded fact, lowercased (`release (…)` -> `release`), or ''."""
    if not isinstance(value, str):
        return ""
    parts = value.strip().split()
    return parts[0].lower() if parts else ""


def git_is_ancestor(commit, repo):
    if not re.fullmatch(r"[0-9a-f]{7,64}", commit or ""):
        return False
    r = subprocess.run(
        ["git", "-C", repo, "merge-base", "--is-ancestor", commit + "^{commit}", "HEAD"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )
    return r.returncode == 0


def git_show(repo, commit, path):
    """(text, None) for `path` as committed at `commit`, or (None, reason). No shell; the
    content is the committed blob, never the working tree."""
    if not re.fullmatch(r"[0-9a-f]{7,64}", commit or ""):
        return None, "record_commit %r is not a hexadecimal commit id" % (commit,)
    r = subprocess.run(
        ["git", "-C", repo, "show", "--no-textconv", "%s:%s" % (commit, path)],
        capture_output=True, check=False,
    )
    if r.returncode != 0:
        return None, "`git show %s:%s` failed" % (commit, path)
    try:
        return r.stdout.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "%s at %s is not UTF-8" % (path, commit)


def repo_relative(path):
    """`path` when it is a normalized, relative, in-repository path; otherwise None."""
    if not path or "\\" in path or "\0" in path or path.startswith("/"):
        return None
    norm = posixpath.normpath(path)
    if norm != path or norm == "." or norm == ".." or norm.startswith("../"):
        return None
    return path


# ⟨M03-F1-R06⟩ Normalizers for the record's host facts. Each returns the bare version token,
# or None when the fact does not have the expected shape. The token must be complete: it is
# followed by end of input, a space or a comma, never by more version-like characters.

def norm_os_release(osn, fact):
    if not isinstance(fact, str):
        return None
    if osn == "macos":  # "macOS 27.2.1 (26B131) arm64" -> the ProductVersion
        m = re.fullmatch(r"macOS (\d+(?:\.\d+)+)(?: .*)?", fact)
    elif osn == "linux":  # "Linux 6.8.0-147-generic x86_64" -> the kernel release
        m = re.fullmatch(r"Linux (\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:[._+~-][0-9A-Za-z]+)*)?)(?: .*)?", fact)
    elif osn == "windows":  # "Microsoft Windows [Version 10.0.26300.9974]"
        m = re.fullmatch(r"Microsoft Windows \[Version (\d+(?:\.\d+){2,3})\]", fact)
    else:
        return None
    return m.group(1) if m else None


def norm_client_version(osn, fact):
    """`OpenSSH_10.5p1, LibreSSL ...` -> `10.5p1`; Windows `OpenSSH_for_Windows_9.5p2, ...`."""
    if not isinstance(fact, str) or osn not in OS_VALUES:
        return None
    prefix = "OpenSSH_for_Windows_" if osn == "windows" else "OpenSSH_"
    m = re.fullmatch(re.escape(prefix) + r"(\d+\.\d+(?:p\d+)?)(?:[ ,].*)?", fact)
    return m.group(1) if m else None


# The host fact that names the client the harness ran, per platform. Windows' `ssh-V-path-first`
# is a candidate that was not selected and is never read.
CLIENT_FACT_KEY = {"macos": "ssh-V", "linux": "ssh-V", "windows": "ssh-V-inbox"}


def workspace_version(cargo_text):
    """The `version` under `[workspace.package]`, or None (absent, duplicated or empty)."""
    in_section, found = False, []
    for line in cargo_text.splitlines():
        s = line.strip()
        if s.startswith("["):
            in_section = re.fullmatch(r"\[\s*workspace\s*\.\s*package\s*\]\s*(#.*)?", s) is not None
        elif in_section:
            m = re.fullmatch(r'version\s*=\s*"([^"\\]*)"\s*(#.*)?', s)
            if m:
                found.append(m.group(1))
    return found[0] if len(found) == 1 and found[0] else None


def _host_fact(record, osn, key):
    env = record.get("environment")
    facts = env.get("host_facts") if isinstance(env, dict) else None
    per_os = facts.get(osn) if isinstance(facts, dict) else None
    value = per_os.get(key) if isinstance(per_os, dict) else None
    return value if isinstance(value, str) and value else None


def check_bounds(tag, e, record, rec, cargo_text, cargo_error):
    """Failures for the entry's version bounds against the record's host facts at its revision."""
    bad = []
    osn = e["platform"]["os"]
    if osn not in OS_VALUES:
        return bad  # reported elsewhere

    def expect(bound, actual, expected, source):
        if expected is None:
            return
        if actual != expected:
            bad.append("%s: %s %r does not equal %s %r" % (tag, bound, actual, source, expected))

    def fact(key):
        value = _host_fact(record, osn, key)
        if value is None:
            bad.append("%s: record %s has no environment.host_facts.%s.%s to check the bounds against" % (tag, rec, osn, key))
        return value

    where = "record %s host_facts.%s" % (rec, osn)
    os_fact = fact("os")
    if os_fact is not None:
        release = norm_os_release(osn, os_fact)
        if release is None:
            bad.append("%s: os_floor cannot be checked: %s.os = %r has no complete OS release" % (tag, where, os_fact))
        expect("os_floor", e["os_floor"], release, "the OS release in %s.os (%r) =" % (where, os_fact))
    key = CLIENT_FACT_KEY[osn]
    client_fact = fact(key)
    if client_fact is not None:
        client = norm_client_version(osn, client_fact)
        if client is None:
            bad.append("%s: client_versions cannot be checked: %s.%s = %r has no complete client version" % (tag, where, key, client_fact))
        for bound in ("min", "max"):
            expect("client_versions.%s" % bound, e["client_versions"][bound], client,
                   "the client version in %s.%s (%r) =" % (where, key, client_fact))
    if cargo_error is not None:
        bad.append("%s: signer_builds cannot be checked: %s" % (tag, cargo_error))
    else:
        signer = workspace_version(cargo_text)
        if signer is None:
            bad.append("%s: signer_builds cannot be checked: Cargo.toml at the cited revision has no single [workspace.package] version" % tag)
        for bound in ("min", "max"):
            expect("signer_builds.%s" % bound, e["signer_builds"][bound], signer,
                   "the [workspace.package] version at the cited revision =")
    return bad


def check_entries(entries, custody, kinds, repo, schema):
    """Return a list of failure strings (empty when the table is valid)."""
    bad = []
    if custody != MIRROR_CUSTODY_FIELDS:
        bad.append("CUSTODY_FIELDS %r disagrees with the validator's mirror %r" % (custody, MIRROR_CUSTODY_FIELDS))
    if kinds != MIRROR_PRODUCT_STORE_KINDS:
        bad.append("product_store_kinds %r disagrees with the validator's mirror %r" % (kinds, MIRROR_PRODUCT_STORE_KINDS))
    for n, e in enumerate(entries):
        tag = "entry %d (%s=%s, %s/%s)" % (n, e["field"], e["value"], e["platform"]["os"], e["platform"]["arch"])
        osn, arch = e["platform"]["os"], e["platform"]["arch"]
        if osn not in OS_VALUES:
            bad.append("%s: unknown platform.os %r" % (tag, osn))
        if arch not in ARCH_VALUES:
            bad.append("%s: unknown platform.arch %r" % (tag, arch))
        if not e["field"] or not e["value"]:
            bad.append("%s: empty field or value" % tag)
        # custody rule (F03)
        if e["field"] in custody or e["field"] in MIRROR_CUSTODY_FIELDS:
            if e["build_profile"] != "Release":
                bad.append("%s: a custody-dependent field needs a Release build profile (found %s)" % (tag, e["build_profile"]))
            sk = e["store_kind"]
            if sk is None or sk in TEST_STORE_KINDS or sk not in MIRROR_PRODUCT_STORE_KINDS.get(osn, []):
                bad.append(
                    "%s: a custody-dependent field needs a product store kind of %s (%s); found %r"
                    % (tag, osn, ", ".join(MIRROR_PRODUCT_STORE_KINDS.get(osn, [])) or "none", sk)
                )
        # record: read at its cited revision, validates, verified for the platform row
        rec = e["record"]
        commit = e["record_commit"]
        record = None
        if repo_relative(rec) is None:
            bad.append("%s: record path %r is empty, absolute or outside the repository" % (tag, rec))
        else:
            text, err = git_show(repo, commit, rec)
            if text is None:
                bad.append("%s: record %s does not exist at record_commit %s (%s)" % (tag, rec, commit, err))
            else:
                try:
                    decoded = json.loads(text)
                except ValueError as exc:
                    bad.append("%s: record %s at %s is not readable JSON (%s)" % (tag, rec, commit, exc))
                else:
                    # ⟨M03-F1-R06 residual⟩ Checked at decoding: a decoded `null` (or any other
                    # non-object) fails, never read as "no record".
                    if isinstance(decoded, dict):
                        record = decoded
                    else:
                        bad.append(
                            "%s: record %s at %s is not a JSON object (decoded %s)"
                            % (tag, rec, commit, type(decoded).__name__)
                        )
        if record is not None:
            errors = minischema.validate(schema, record)
            if errors:
                bad.append("%s: record %s does not validate: %s" % (tag, rec, "; ".join(errors[:3])))
            rows = [r for r in record_rows(record) if row_platform(r) == (osn, arch)]
            if not rows:
                bad.append("%s: record %s has no row for platform %s/%s" % (tag, rec, osn, arch))
            for r in rows:
                if r.get("status") != "verified":
                    bad.append(
                        "%s: record %s row for %s/%s is %r, not verified"
                        % (tag, rec, osn, arch, r.get("status"))
                    )
            # ⟨M03 wave 6, W6-R03⟩ A custody claim's declaration must match the
            # provenance its evidence row recorded (the run's `build-profile` and
            # `store-kind` facts, carried into the row by the evidence generator): a
            # debug or test-store run never feeds a custody field, whatever the entry says.
            if rows and (e["field"] in custody or e["field"] in MIRROR_CUSTODY_FIELDS):
                prov = [
                    r for r in rows
                    if _first_word(r.get("build_profile")) == "release"
                    and _first_word(r.get("store_kind")) == (e["store_kind"] or "")
                ]
                if not prov:
                    found = ", ".join(
                        "%s/%s" % (_first_word(r.get("build_profile")) or "unrecorded",
                                   _first_word(r.get("store_kind")) or "unrecorded")
                        for r in rows
                    )
                    bad.append(
                        "%s: record %s has no %s/%s row whose recorded run is a release build on store kind %r (the rows record %s)"
                        % (tag, rec, osn, arch, e["store_kind"], found)
                    )
            cargo_text, cargo_error = git_show(repo, commit, "Cargo.toml")
            bad.extend(check_bounds(tag, e, record, rec, cargo_text or "", cargo_error))
        if not git_is_ancestor(e["record_commit"], repo):
            bad.append("%s: record_commit %r is not a commit that is an ancestor of HEAD" % (tag, e["record_commit"]))
    return bad


def load_schema():
    with open(SCHEMA, encoding="utf-8") as f:
        schema = json.load(f)
    if not minischema.validate(schema, {"status": "not-a-status"}):
        raise SystemExit("claims_table: self-check failed: an invalid record was accepted")
    return schema


def check_source(source, record_root, repo, schema):
    entries, custody, kinds = parse_claims(source)
    residuals = parse_residuals(source)
    bad = check_entries(entries, custody, kinds, repo, schema)
    return entries, bad + check_residuals(residuals, entries, record_root)


# ---------------------------------------------------------------------------
# Self-tests

FIXTURE_CARGO_VERSION = "0.1.0-fixture"
FIXTURE_HOST_FACTS = {
    "macos": {"os": "macOS 27.2.1 (26B131) arm64", "ssh-V": "OpenSSH_10.5p1, LibreSSL 3.3.6 (exit 0)"},
    "linux": {
        "os": "Linux 6.8.0-147-generic x86_64",
        "ssh-V": "OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.0.13 30 Jan 2024 (exit 0)",
    },
    "windows": {
        "os": "Microsoft Windows [Version 10.0.26300.9974]",
        "ssh-V-inbox": "OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2",
        "ssh-V-path-first": "OpenSSH_10.3p1, OpenSSL 3.5.7 9 Jun 2026 (candidate, not selected)",
    },
}
# (os_floor, client version) the fixture records normalize to, per platform.
FIXTURE_BOUNDS = {
    "macos": ("27.2.1", "10.5p1"),
    "linux": ("6.8.0-147-generic", "9.6p1"),
    "windows": ("10.0.26300.9974", "9.5p2"),
}
FIXTURE_COMMIT = "@FIXTURE_COMMIT@"  # replaced by the fixture repository's commit


def _record(status, platform="windows-11-x86_64", build_profile="release (fixture)", store_kind="windows_dpapi",
            environment=None):
    row = {"platform": platform, "status": status}
    if build_profile is not None:
        row["build_profile"] = build_profile
    if store_kind is not None:
        row["store_kind"] = store_kind
    return {
        "case_id": "m03-a03-fixture",
        "status": status,
        "requirement_ids": [],
        "build_commit": None,
        "artifact_digest": None,
        "environment": {"host_facts": FIXTURE_HOST_FACTS} if environment is None else environment,
        "provider_versions": [],
        "started_at": None,
        "commands_or_harness": None,
        "observed_result": {"rows": [row]},
        "evidence_paths": [],
        "limitations": [],
        **({"blocked_on": "fixture: a missing platform"} if status == "blocked" else {}),
    }


def _entry_source(field="lock_continuity", value="verified", os_="windows", arch="x86_64",
                  profile="Release", store='Some("windows_dpapi")', record="tests/evidence/rec.json", commit=None,
                  os_floor=None, client_min=None, client_max=None,
                  signer_min=FIXTURE_CARGO_VERSION, signer_max=FIXTURE_CARGO_VERSION):
    floor, client = FIXTURE_BOUNDS.get(os_, ("", ""))
    return (
        "//! fixture\n"
        "pub const CUSTODY_FIELDS: &[&str] = &[\"lock_continuity\"];\n"
        "pub fn product_store_kinds(os: &str) -> &'static [&'static str] {\n"
        "    match os {\n"
        "        \"macos\" => &[\"macos_login_keychain\", \"macos_data_protection_keychain\"],\n"
        "        \"windows\" => &[\"windows_dpapi\"],\n"
        "        \"linux\" => &[\"linux_secret_service\"],\n"
        "        _ => &[],\n    }\n}\n"
        "pub const CLAIMS: &[Claim] = &[\n"
        "    // a comment, with \"quotes\" and a ] bracket\n"
        "    Claim {\n"
        "        field: \"%s\", value: \"%s\",\n"
        "        platform: Platform { os: \"%s\", arch: \"%s\" },\n"
        "        os_floor: \"%s\",\n"
        "        client_versions: VersionRange { min: \"%s\", max: \"%s\" },\n"
        "        signer_builds: VersionRange { min: \"%s\", max: \"%s\" },\n"
        "        build_profile: BuildProfile::%s,\n"
        "        store_kind: %s,\n"
        "        record: \"%s\",\n"
        "        record_commit: \"%s\", /* trailing */\n"
        "    },\n"
        "];\n" % (
            field, value, os_, arch,
            floor if os_floor is None else os_floor,
            client if client_min is None else client_min,
            client if client_max is None else client_max,
            signer_min, signer_max, profile, store, record, commit or FIXTURE_COMMIT,
        )
    )


def _fixture_cargo(version):
    return '[workspace]\nmembers = []\n\n[workspace.package]\nversion = "%s"\nedition = "2024"\n' % version


def _git_fixture(tmp, *args):
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    r = subprocess.run(
        ["git", "-C", tmp, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
         "-c", "commit.gpgsign=false"] + list(args),
        capture_output=True, text=True, check=False, env=env,
    )
    if r.returncode != 0:
        raise RuntimeError("fixture git %s failed: %s" % (args[0], r.stderr.strip()))
    return r.stdout.strip()


def _commit_fixture(tmp, files, message="fixture"):
    """Write `files` ({relative path: text, or a JSON-able record}) into the fixture repository,
    commit everything and return the commit id."""
    for rel, content in files.items():
        path = os.path.join(tmp, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content if isinstance(content, str) else json.dumps(content))
    _git_fixture(tmp, "add", "-A")
    _git_fixture(tmp, "commit", "-q", "--allow-empty", "-m", message)
    return _git_fixture(tmp, "rev-parse", "HEAD")


def _run_fixture(source, record=None, extra_files=None, cargo_version=FIXTURE_CARGO_VERSION):
    """Check `source` against a temporary git repository holding `record`, a workspace
    Cargo.toml and `extra_files` in one commit (the placeholder commit in `source` is that
    commit); the same repository is the record root and the repo whose HEAD is the ancestor."""
    tmp = tempfile.mkdtemp(prefix="claims-table-fixture-")
    try:
        _git_fixture(tmp, "init", "-q")
        files = {"Cargo.toml": _fixture_cargo(cargo_version)}
        if record is not None:
            files["tests/evidence/rec.json"] = record
        files.update(extra_files or {})
        sha = _commit_fixture(tmp, files)
        return check_source(source.replace(FIXTURE_COMMIT, sha), tmp, tmp, load_schema())[1]
    finally:
        shutil.rmtree(tmp)


def _run_history_fixture(make_source, early, late):
    """Two commits in a temporary repository: `early` files, then `late` files (HEAD).
    `make_source(early_sha, late_sha)` returns the table source."""
    tmp = tempfile.mkdtemp(prefix="claims-table-history-")
    try:
        _git_fixture(tmp, "init", "-q")
        first = _commit_fixture(tmp, early, "early")
        second = _commit_fixture(tmp, late, "late")
        return check_source(make_source(first, second), tmp, tmp, load_schema())[1]
    finally:
        shutil.rmtree(tmp)


def _has(bad, *needles):
    return any(all(n in b for n in needles) for b in bad)


def _t_empty():
    with open(CLAIMS_RS, encoding="utf-8") as f:
        source = f.read()
    # ⟨M03 claim update⟩ The baseline form: the real file with its table emptied validates
    # (the real table's entries are validated by the main step).
    empty = re.sub(
        r"(pub\s+const\s+CLAIMS\s*:\s*&\s*\[\s*Claim\s*\]\s*=\s*&\s*\[).*?(\n\];)",
        r"\1\2",
        source,
        count=1,
        flags=re.S,
    )
    entries, bad = check_source(empty, ROOT, ROOT, load_schema())
    return len(entries) == 0 and not bad, bad


def _t_blocked():
    bad = _run_fixture(_entry_source(), _record("blocked"))
    return _has(bad, "row for windows/x86_64 is 'blocked', not verified"), bad


def _t_debug_or_test_store():
    rec = _record("verified")
    bad1 = _run_fixture(_entry_source(profile="Debug"), rec)
    ok1 = _has(bad1, "Release build profile") and not _has(bad1, "product store kind")
    bad2 = _run_fixture(_entry_source(store='Some("scratch_test")'), rec)
    ok2 = _has(bad2, "product store kind", "scratch_test") and not _has(bad2, "Release build profile")
    bad3 = _run_fixture(_entry_source(store="None"), rec)
    ok3 = _has(bad3, "product store kind")
    return ok1 and ok2 and ok3, bad1 + bad2 + bad3


def _t_custody_row_provenance():
    """W6-R03: a verified row whose recorded run was a debug build on the scratch test
    store never feeds a custody claim, even when the entry declares Release and a product
    store (the reviewer's contradictory row); a row with no recorded provenance neither."""
    rec = _record("verified", platform="macos-arm64 (debug build, scratch test store)",
                  build_profile="debug (test configuration)", store_kind="scratch_test (the test store)")
    bad = _run_fixture(_entry_source(os_="macos", arch="aarch64", store='Some("macos_login_keychain")'), rec)
    ok1 = _has(bad, "no macos/aarch64 row whose recorded run is a release build", "debug/scratch_test")
    unrecorded = _record("verified", build_profile=None, store_kind=None)
    bad2 = _run_fixture(_entry_source(), unrecorded)
    ok2 = _has(bad2, "whose recorded run is a release build", "unrecorded/unrecorded")
    return ok1 and ok2, bad + bad2


def _t_positive():
    rec = _record("verified")
    ok_valid = not _run_fixture(_entry_source(), rec)
    # Not an ancestor of HEAD, a missing record, a platform without a row, a parse error.
    bad_commit = _run_fixture(_entry_source(commit="0" * 40), rec)
    bad_missing = _run_fixture(_entry_source(record="tests/evidence/nope.json"), rec)
    bad_platform = _run_fixture(_entry_source(os_="linux", store='Some("linux_secret_service")'), rec)
    bad_traversal = _run_fixture(_entry_source(record="../outside.json"), rec)
    try:
        _run_fixture(re.sub(r'os_floor: "[^"]*",', "", _entry_source()), rec)
        parse_fails = False
    except ParseError:
        parse_fails = True
    ok = (
        ok_valid
        and _has(bad_commit, "not a commit that is an ancestor")
        and _has(bad_missing, "does not exist")
        and _has(bad_platform, "no row for platform linux/x86_64")
        and _has(bad_traversal, "outside the repository")
        and parse_fails
    )
    return ok, bad_commit + bad_missing + bad_platform + bad_traversal


def _t_unrelated_bounds():
    """M03-F1-R06: bounds unrelated to the record's host facts fail, one message per bound."""
    rec = _record("verified")
    bad = _run_fixture(_entry_source(os_floor="99.9", client_min="1.0p1", client_max="2.0p2",
                                     signer_min="0.0.1", signer_max="9.9.9"), rec)
    ok = (
        _has(bad, "os_floor '99.9'", "10.0.26300.9974")
        and _has(bad, "client_versions.min '1.0p1'", "9.5p2", "ssh-V-inbox")
        and _has(bad, "client_versions.max '2.0p2'", "9.5p2")
        and _has(bad, "signer_builds.min '0.0.1'", FIXTURE_CARGO_VERSION)
        and _has(bad, "signer_builds.max '9.9.9'", FIXTURE_CARGO_VERSION)
    )
    # A range is not an identity: min right, max wrong fails the max only.
    bad2 = _run_fixture(_entry_source(signer_max="0.2.0"), rec)
    ok2 = _has(bad2, "signer_builds.max '0.2.0'") and not _has(bad2, "signer_builds.min")
    # Windows' ssh-V-path-first is a candidate that was not selected.
    bad3 = _run_fixture(_entry_source(client_min="10.3p1", client_max="10.3p1"), rec)
    ok3 = _has(bad3, "client_versions.min '10.3p1'") and _has(bad3, "client_versions.max '10.3p1'")
    # A record without host facts cannot back any bound.
    bad4 = _run_fixture(_entry_source(), _record("verified", environment="fixture"))
    ok4 = _has(bad4, "no environment.host_facts.windows.os") and _has(bad4, "host_facts.windows.ssh-V-inbox")
    # The exact bounds on each platform pass (the positive control for the above).
    ok5 = all(
        not _run_fixture(
            _entry_source(os_=o, store='Some("%s")' % MIRROR_PRODUCT_STORE_KINDS[o][0]),
            _record("verified", platform="%s-%s" % (o, "x86_64"), store_kind=MIRROR_PRODUCT_STORE_KINDS[o][0]),
        )
        for o in ("macos", "linux", "windows")
    )
    return ok and ok2 and ok3 and ok4 and ok5, bad + bad2 + bad3 + bad4


def _t_revision_reading():
    """M03-F1-R06: the record and Cargo.toml are read at record_commit, not from the working
    tree. An ancestor commit that predates the record fails even though HEAD has a verified row."""
    cargo = {"Cargo.toml": _fixture_cargo(FIXTURE_CARGO_VERSION)}
    verified = {"tests/evidence/rec.json": _record("verified")}
    # (b) the record is added after the cited commit.
    bad = _run_history_fixture(lambda early, late: _entry_source(commit=early), cargo, verified)
    ok = _has(bad, "record tests/evidence/rec.json does not exist at record_commit")
    # The same table citing the commit that has the record passes.
    ok_valid = not _run_history_fixture(lambda early, late: _entry_source(commit=late), cargo, verified)
    # The cited revision's row is not verified though the working tree's is.
    blocked = dict(cargo, **{"tests/evidence/rec.json": _record("blocked")})
    bad2 = _run_history_fixture(lambda early, late: _entry_source(commit=early), blocked, verified)
    ok2 = _has(bad2, "row for windows/x86_64 is 'blocked', not verified")
    # The signer version is the one at the cited revision, not HEAD's.
    old_cargo = dict(verified, **{"Cargo.toml": _fixture_cargo("0.0.1-old")})
    bad3 = _run_history_fixture(lambda early, late: _entry_source(commit=early), old_cargo, cargo)
    ok3 = _has(bad3, "signer_builds.min", "0.0.1-old") and _has(bad3, "signer_builds.max", "0.0.1-old")
    # No Cargo.toml at the cited revision: the signer bounds cannot be checked.
    bad4 = _run_history_fixture(lambda early, late: _entry_source(commit=early), verified, cargo)
    ok4 = _has(bad4, "signer_builds cannot be checked")
    return ok and ok_valid and ok2 and ok3 and ok4, bad + bad2 + bad3 + bad4


def _t_non_object_record():
    """M03-F1-R06 residual: a cited record that decodes to `null` (or another non-object)
    fails, even when HEAD's record is verified."""
    cargo = {"Cargo.toml": _fixture_cargo(FIXTURE_CARGO_VERSION)}
    verified = {"tests/evidence/rec.json": _record("verified")}
    bad = []
    ok = True
    for text in ("null", "[]", '"verified"', "3"):
        early = dict(cargo, **{"tests/evidence/rec.json": text})
        b = _run_history_fixture(lambda first, late: _entry_source(commit=first), early, verified)
        ok = ok and _has(b, "record tests/evidence/rec.json at", "is not a JSON object")
        bad += b
    return ok, bad


def _t_normalizers_strict():
    """M03-F1-R06: the host-fact normalizers take a complete version token or nothing."""
    pos = [
        norm_os_release("macos", "macOS 27.2.1 (26B131) arm64") == "27.2.1",
        norm_os_release("macos", "macOS 27.3") == "27.3",
        norm_os_release("linux", "Linux 6.8.0-147-generic x86_64") == "6.8.0-147-generic",
        norm_os_release("windows", "Microsoft Windows [Version 10.0.26300.9974]") == "10.0.26300.9974",
        norm_client_version("macos", "OpenSSH_10.5p1, LibreSSL 3.3.6 (exit 0)") == "10.5p1",
        norm_client_version("linux", "OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.0.13 (exit 0)") == "9.6p1",
        norm_client_version("windows", "OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2") == "9.5p2",
        workspace_version('[package]\nversion = "9"\n[workspace.package]\nversion = "0.1.0-m01"\nedition = "2024"\n') == "0.1.0-m01",
    ]
    neg = [
        norm_client_version("linux", "OpenSSH_9.6p1broken, OpenSSL") is None,
        norm_client_version("macos", "OpenSSH_10.5p1x") is None,
        norm_client_version("windows", "OpenSSH_9.5p2, LibreSSL") is None,  # not the Windows build
        norm_client_version("macos", "OpenSSH_for_Windows_9.5p2") is None,
        norm_client_version("macos", "OpenSSH_10.5p1.") is None,
        norm_os_release("macos", "macOS 27.3.") is None,
        norm_os_release("macos", "macOS 27.3beta arm64") is None,
        norm_os_release("linux", "Linux 6.8.0- x86_64") is None,
        norm_os_release("linux", "Linux 6.8 x86_64") is None,
        norm_os_release("windows", "Microsoft Windows [Version 10.0.26300.9974") is None,
        norm_os_release("windows", "Microsoft Windows [Version 10.0.26300.]") is None,
        norm_os_release("macos", None) is None,
        workspace_version('[workspace.package]\nedition = "2024"\n[other]\nversion = "1"\n') is None,
        workspace_version('[workspace.package]\nversion = "1"\nversion = "2"\n') is None,
    ]
    # And through a whole entry: a client string that does not normalize fails it.
    broken = {"host_facts": dict(FIXTURE_HOST_FACTS, linux={
        "os": "Linux 6.8.0-147-generic x86_64", "ssh-V": "OpenSSH_9.6p1broken, OpenSSL 3.0.13 (exit 0)"})}
    bad = _run_fixture(
        _entry_source(os_="linux", store='Some("linux_secret_service")'),
        _record("verified", platform="linux-x86_64", store_kind="linux_secret_service", environment=broken),
    )
    ok_entry = _has(bad, "client_versions cannot be checked", "OpenSSH_9.6p1broken")
    return all(pos) and all(neg) and ok_entry, ["pos %r neg %r" % (pos, neg)] + bad


def _residual_source(rid="uninstall_fixture_residual", extra="", source="crates/x/src/lib.rs",
                     test="x::tests::the_probe"):
    return (
        "pub const RESIDUALS: &[Residual] = &[\n"
        "    Residual {\n"
        "        id: \"%s\",\n"
        "        description: \"a fixture residual\",\n"
        "        platform: Platform { os: \"any\", arch: \"any\" },\n"
        "        limits: \"lock_continuity\",\n"
        "        probe: Probe { target: \"-p x\", source: \"%s\", test: \"%s\" },\n"
        "        reason: ResidualReason::NeedsHostileSameUserProgram,\n"
        "        adr: \"ADR-0008 §17.33 item 7\",%s\n"
        "    },\n"
        "];\n" % (rid, source, test, extra)
    )


def _run_residual_fixture(residual, with_probe=True, probe_src=None):
    extra = {}
    if with_probe:
        extra["crates/x/src/lib.rs"] = probe_src or "#[cfg(test)]\nmod tests {\n    #[test]\n    fn the_probe() {}\n}\n"
    return _run_fixture(_entry_source() + residual, _record("verified"), extra_files=extra)


def _t_residual_verified():
    bad = _run_residual_fixture(_residual_source(extra='\n        status: "verified",'))
    bad2 = _run_residual_fixture(_residual_source(extra='\n        value: "verified",'))
    msg = "a residual is never a verified claim"
    return _has(bad, msg, "status") and _has(bad2, msg, "value"), bad + bad2


def _t_residual_as_claim():
    bad = _run_residual_fixture(_residual_source(rid="lock_continuity"))
    return _has(bad, "its id is a CLAIMS field"), bad


def _t_residual_without_test():
    bad = _run_residual_fixture(_residual_source(), with_probe=False)
    bad2 = _run_residual_fixture(_residual_source(test="x::tests::no_such_test"))
    return (
        _has(bad, "probe source crates/x/src/lib.rs does not exist")
        and _has(bad2, "does not define the test x::tests::no_such_test")
    ), bad + bad2


def _t_residual_positive():
    ok = not _run_residual_fixture(_residual_source())
    try:
        _run_residual_fixture(_residual_source(extra='\n        colour: "blue",'))
        parse_fails = False
    except ParseError:
        parse_fails = True
    return ok and parse_fails, []


def _t_residual_tokio_args_and_code():
    tokio = "mod tests {\n    #[tokio::test(flavor = \"multi_thread\")]\n    async fn the_probe() {}\n}\n"
    ok_tokio = not _run_residual_fixture(_residual_source(), probe_src=tokio)
    code = _residual_source(test="").replace('target: \"-p x\"', 'target: \"code: lib.rs\"')
    ok_code = not _run_residual_fixture(code)
    bad = _run_residual_fixture(_residual_source(test=""))
    return ok_tokio and ok_code and _has(bad, "no code is cited"), bad


SELF_TESTS = [
    ("claims_table_residual_tokio_test_with_args_and_code_citation", _t_residual_tokio_args_and_code),
    ("claims_table_rejects_residual_marked_verified", _t_residual_verified),
    ("claims_table_rejects_residual_presented_as_claim", _t_residual_as_claim),
    ("claims_table_rejects_residual_without_its_test", _t_residual_without_test),
    ("claims_table_residual_positive_control", _t_residual_positive),
    ("claims_table_empty_validates", _t_empty),
    ("claims_table_rejects_entry_for_blocked_record", _t_blocked),
    ("claims_table_rejects_debug_profile_or_test_store_for_custody_claim", _t_debug_or_test_store),
    ("claims_table_rejects_custody_claim_whose_evidence_row_is_debug_or_test_store", _t_custody_row_provenance),
    ("claims_table_positive_control", _t_positive),
    ("claims_table_rejects_bounds_unrelated_to_the_record", _t_unrelated_bounds),
    ("claims_table_reads_the_record_at_its_cited_revision", _t_revision_reading),
    ("claims_table_host_fact_normalizers_are_strict", _t_normalizers_strict),
    ("claims_table_rejects_a_cited_record_that_is_not_an_object", _t_non_object_record),
]


def self_tests():
    failed = 0
    for name, fn in SELF_TESTS:
        try:
            ok, detail = fn()
        except Exception as exc:  # a crashing self-test is a failing one
            ok, detail = False, ["exception: %r" % (exc,)]
        print("self-test %s: %s" % (name, "PASS" if ok else "FAIL"))
        if not ok:
            failed += 1
            for d in detail:
                print("    observed: " + d)
    return failed


def main(argv):
    if any(a not in ("--self-test",) for a in argv):
        sys.stderr.write("claims_table: unknown arguments\n")
        return 2
    rc = 0
    if "--self-test" not in argv:
        try:
            with open(CLAIMS_RS, encoding="utf-8") as f:
                source = f.read()
            entries, bad = check_source(source, ROOT, ROOT, load_schema())
        except (OSError, ParseError) as exc:
            print("FAIL: %s: %s" % (os.path.relpath(CLAIMS_RS, ROOT), exc))
            rc = 1
        else:
            print("claims table: %d entr%s" % (len(entries), "y" if len(entries) == 1 else "ies"))
            print("residuals: %d" % len(parse_residuals(source)))
            for b in bad:
                print("VIOLATION: " + b)
            if bad:
                rc = 1
            else:
                print("claims table: OK")
    if self_tests():
        rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
