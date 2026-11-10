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
  * `record` resolves inside the repository, exists, and validates against
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
  * for custody-dependent fields (`CUSTODY_FIELDS`, read from the same file): the build
    profile is `Release` and `store_kind` is one of the platform's product store kinds
    (`product_store_kinds(os)`, read from the same file and checked against the mirror
    below; the two must agree). Test-store evidence never satisfies a product-store claim.

The empty table passes (the M03 baseline). Self-tests, each printed with PASS or FAIL,
build fixture tables and records in a `tempfile.mkdtemp()` directory removed afterwards:
  claims_table_empty_validates
  claims_table_rejects_entry_for_blocked_record
  claims_table_rejects_debug_profile_or_test_store_for_custody_claim
  claims_table_positive_control (a valid fixture entry passes; a parse error fails)
"""
import json
import os
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

def git_is_ancestor(commit, repo):
    if not re.fullmatch(r"[0-9a-f]{7,64}", commit or ""):
        return False
    r = subprocess.run(
        ["git", "-C", repo, "merge-base", "--is-ancestor", commit + "^{commit}", "HEAD"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )
    return r.returncode == 0


def check_entries(entries, custody, kinds, record_root, repo, schema):
    """Return a list of failure strings (empty when the table is valid)."""
    bad = []
    if custody != MIRROR_CUSTODY_FIELDS:
        bad.append("CUSTODY_FIELDS %r disagrees with the validator's mirror %r" % (custody, MIRROR_CUSTODY_FIELDS))
    if kinds != MIRROR_PRODUCT_STORE_KINDS:
        bad.append("product_store_kinds %r disagrees with the validator's mirror %r" % (kinds, MIRROR_PRODUCT_STORE_KINDS))
    real_root = os.path.realpath(record_root)
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
        # record: exists inside the repo, validates, verified for the platform row
        rec = e["record"]
        path = os.path.realpath(os.path.join(real_root, rec))
        if not rec or os.path.isabs(rec) or not (path == real_root or path.startswith(real_root + os.sep)):
            bad.append("%s: record path %r is empty, absolute or outside the repository" % (tag, rec))
        elif not os.path.isfile(path):
            bad.append("%s: record %s does not exist" % (tag, rec))
        else:
            try:
                with open(path, encoding="utf-8") as f:
                    record = json.load(f)
            except (OSError, ValueError) as exc:
                bad.append("%s: record %s is not readable JSON (%s)" % (tag, rec, exc))
                record = None
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
    return entries, check_entries(entries, custody, kinds, record_root, repo, schema)


# ---------------------------------------------------------------------------
# Self-tests

def head_commit():
    r = subprocess.run(["git", "-C", ROOT, "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    return r.stdout.strip()


def _record(status, platform="windows-11-x86_64"):
    return {
        "case_id": "m03-a03-fixture",
        "status": status,
        "requirement_ids": [],
        "build_commit": None,
        "artifact_digest": None,
        "environment": "fixture",
        "provider_versions": [],
        "started_at": None,
        "commands_or_harness": None,
        "observed_result": {"rows": [{"platform": platform, "status": status}]},
        "evidence_paths": [],
        "limitations": [],
        **({"blocked_on": "fixture: a missing platform"} if status == "blocked" else {}),
    }


def _entry_source(field="lock_continuity", value="verified", os_="windows", arch="x86_64",
                  profile="Release", store='Some("windows_dpapi")', record="tests/evidence/rec.json", commit=None):
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
        "        os_floor: \"11\",\n"
        "        client_versions: VersionRange { min: \"9.0\", max: \"\" },\n"
        "        signer_builds: VersionRange { min: \"0.1.0\", max: \"\" },\n"
        "        build_profile: BuildProfile::%s,\n"
        "        store_kind: %s,\n"
        "        record: \"%s\",\n"
        "        record_commit: \"%s\", /* trailing */\n"
        "    },\n"
        "];\n" % (field, value, os_, arch, profile, store, record, commit or head_commit())
    )


def _run_fixture(source, record=None):
    tmp = tempfile.mkdtemp(prefix="claims-table-fixture-")
    try:
        if record is not None:
            os.makedirs(os.path.join(tmp, "tests", "evidence"))
            with open(os.path.join(tmp, "tests", "evidence", "rec.json"), "w", encoding="utf-8") as f:
                json.dump(record, f)
        return check_source(source, tmp, ROOT, load_schema())[1]
    finally:
        shutil.rmtree(tmp)


def _has(bad, *needles):
    return any(all(n in b for n in needles) for b in bad)


def _t_empty():
    with open(CLAIMS_RS, encoding="utf-8") as f:
        source = f.read()
    entries, bad = check_source(source, ROOT, ROOT, load_schema())
    # The real baseline is empty; a nonempty real table is validated by the main step.
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


def _t_positive():
    rec = _record("verified")
    ok_valid = not _run_fixture(_entry_source(), rec)
    # Not an ancestor of HEAD, a missing record, a platform without a row, a parse error.
    bad_commit = _run_fixture(_entry_source(commit="0" * 40), rec)
    bad_missing = _run_fixture(_entry_source(record="tests/evidence/nope.json"), rec)
    bad_platform = _run_fixture(_entry_source(os_="linux", store='Some("linux_secret_service")'), rec)
    bad_traversal = _run_fixture(_entry_source(record="../outside.json"), rec)
    try:
        _run_fixture(_entry_source().replace("os_floor: \"11\",", ""), rec)
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


SELF_TESTS = [
    ("claims_table_empty_validates", _t_empty),
    ("claims_table_rejects_entry_for_blocked_record", _t_blocked),
    ("claims_table_rejects_debug_profile_or_test_store_for_custody_claim", _t_debug_or_test_store),
    ("claims_table_positive_control", _t_positive),
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
