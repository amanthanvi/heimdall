#!/usr/bin/env python3
"""Check the adapter guide (docs/user/adapters.md) against its sources.

What is checked, and against what (⟨M07-W1-R06⟩):

- Support tables. Each setup has a fixed list of compatibility-matrix rows (SETUPS). The page
  must cite exactly those rows, and each row must still describe that setup in the matrix,
  so evidence for another setup cannot stand in because it has the same label. The visible
  label is the matrix label. In the description, **Verified** and **Blocked** are derived:
  each appears exactly when a cited row's evidence says so, and only in bold.
- Guarantee table. Each sentence is one of BEHAVIORS, backed by CLAIMS entries for that
  platform with exactly the displayed OS floor, versions and build profile.
- Known limits. Each row is the reviewed wording for its RESIDUALS entry (KNOWN_LIMITS), and
  the entry still has the text that wording was reviewed against.
- Guarded sentences. A sentence about revocation, expiry or a guarantee, or one with a
  universal word (GUARDED), must be one of the REVIEWED sentences. This covers the prose
  outside the tables and the support descriptions.
- Tables. A table that is none of the three kinds above is refused.

What is not checked: the rest of the prose is editorial. The descriptions of what was tested
are checked only for their status words and for guarded sentences, so a claim worded without
a guarded word passes, and so does a removed sentence. The page says so in its own note.

A self-check then mutates the page and its sources, and every mutant must be rejected.

Usage: python3 -I -B tools/validation/adapter_page_check.py
Exit: 0 clean, 1 a finding or a failed self-check.
"""

import hashlib
import re
import runpy
import sys
from pathlib import Path
from typing import NamedTuple


ROOT = Path(__file__).resolve().parents[2]
TABLE = re.compile(r"(?m)(?:^\|[^\n]*\|[ \t]*(?:\n|$))+")
SUPPORT = ("Setup", "Support label", "What was tested and what is still open", "Matrix rows")
GUARANTEES = (
    "Native managed-certificate platform", "OS floor", "OpenSSH", "Heimdall signer",
    "Evidence build", "Verified behavior",
)
LIMITS = ("Where", "Known limit")
PLATFORMS = {
    "macOS arm64": ("macos", "aarch64"),
    "Linux x86-64": ("linux", "x86_64"),
    "Windows x86-64": ("windows", "x86_64"),
}
# Check the visible sentences directly so the displayed guarantees cannot drift from their keys.
BEHAVIORS = {
    "The signer stops new signatures at expiry.": [("new_signing_expiry", "signer")],
    "The certificate and signer stop new logins at expiry.": [("new_authentication_expiry", "credential_and_signer")],
    "Strict expiry closes connections Heimdall controls.": [("existing_connections", "strict_disconnect")],
    "Graceful expiry can leave dedicated connections open.": [("existing_connections", "graceful_dedicated_connections")],
    "Shared SSH connections Heimdall manages close at expiry.": [("owned_multiplexing", "closed_at_deadline")],
    "Remote revocation is bounded by certificate expiry.": [
        ("enforcement.revocation", "bounded_by_credential_expiry"),
        ("revocation.remote", "bounded_by_credential_expiry"),
    ],
}

# Each setup's evidence, in the order the page cites it: (words that the matrix row's own
# environment, client, signer or mechanism cells must contain, the rows).
SETUPS = {
    "OpenSSH agent on macOS arm64": (("macOS", "M02-1 M02-2 M02-3 M02-4 M02-17"),),
    "OpenSSH agent on Linux x86-64": (("Linux x86-64", "M02-5 M02-6 M02-7 M02-8"),),
    "OpenSSH agent on Linux arm64": (("Linux arm64", "M02-20"),),
    "OpenSSH agent on Windows x86-64": (("Windows", "16 M02-9 M02-10 M02-11 M02-12 M02-13 M02-18"),),
    "OpenSSH agent inside WSL2": (("WSL2", "M02-19"),),
    "1Password on macOS arm64, Linux x86-64 or Windows x86-64": (("1Password", "M02-14 M02-15 M02-16"),),
    "1Password on Linux arm64": (("1Password", "5"), ("Linux arm64", "M02-20")),
    "Native macOS arm64": (("macOS", "M03-1 M03-6 M03-8"),),
    "Native Linux x86-64": (("Linux", "M03-3 M03-9"),),
    "Native Linux arm64": (("arm64", "6 M05-5"),),
    "Native Windows x86-64": (("Windows", "M03-4 M03-7"),),
    "Managed access inside WSL2": (("WSL2", "M03-5"),),
    "WSL2 Mode A": (("Mode A", "M04-2"),),
    "WSL2 Mode B": (("Mode B", "M04-3 M04-7"),),
    "Local Linux containers": (("container", "M04-4 M04-8 M04-9"),),
    "Jump host via OpenSSH `ProxyJump`": (("ProxyJump", "M04-5"),),
    "Bash and Zsh on macOS arm64, Linux x86-64 and WSL2": (
        ("macOS", "M05-1"), ("Linux x86-64", "M05-2"), ("WSL", "M05-4"), ("Linux arm64", "M05-5"),
    ),
    "Native Windows trusted-project access": (("Windows", "M05-3"),),
}

# Residual ID -> (where it applies, the reviewed sentence, `residual_digest` of the RESIDUALS
# entry the sentence was reviewed against). When an entry changes, read the sentence against
# the new text before recording the new digest.
KNOWN_LIMITS = {
    "same_user_agent_with_a_terminal_can_attend": (
        "Managed access and trusted projects",
        "A program running as you with a terminal can answer Heimdall's confirmation itself.",
        "a27f2cdc0eea96bd",
    ),
    "request_working_directory_is_a_same_user_claim": (
        "Trusted projects and shell integration",
        "A program running as you can name a trusted project's directory and activate the access already approved "
        "for that project.",
        "f586535a712aff4d",
    ),
    "first_ordinary_ssh_after_a_free_slot_fails_once": (
        "Ordinary `ssh` with personal managed access",
        "The first `ssh` after the personal access slot goes idle may start access but fail to connect. Retry once. "
        "The tested Bash and Zsh hooks prepare access before the first `ssh`.",
        "150d5284831bc7d7",
    ),
    "workspace_identity_unavailable_is_refused": (
        "Trusted projects and shell integration",
        "Heimdall refuses to match a project to saved trust if its filesystem can't report a stable identity for "
        "the project files.",
        "683b54e843da973f",
    ),
    "issuer_request_hold_absent_for_leader_and_lease_work": (
        "Managed certificate signing during uninstall",
        "If a signing request times out during an access check or work allowed through the uninstall pause, "
        "uninstall can proceed while the signing process is still running. A late signature can't publish a "
        "certificate.",
        "e8c484046e010719",
    ),
    "issuer_cleanup_cancelled_kill_on_drop_signals_unreaped_child": (
        "Managing a timed-out certificate signing process",
        "If cleanup is cancelled while waiting for a timed-out signing process, it can signal that child before it "
        "verifies the child's identity. The signal is limited to the child it started, and the request leaves no "
        "certificate behind.",
        "a4e052d4d6060bde",
    ),
}

# A sentence with one of these words makes a claim about revocation, expiry or a guarantee, or
# a universal one. It must be reviewed wording.
GUARDED = re.compile(
    r"(?i)\b(?:revo[ck]\w*|expir\w*|guarantee\w*|immediate\w*|instant\w*|at once|right away|always|never"
    r"|every\w*|all|any\w*)\b"
)
REVIEWED = {
    # Prose outside the tables.
    "The managed-certificate guarantees below apply to Heimdall's own signer.",
    "The managed-certificate guarantees depend on the Windows runtime's verified client, which may differ from "
    "the client Git calls from WSL.",
    "Mode B and container endpoints have no guarantees in the claims table.",
    "A jump route adds no guarantees of its own.",
    # enforcement.revocation and revocation.remote: bounded_by_credential_expiry.
    "If a remote machine is offline, immediate revocation may be unavailable.",
    "An issued certificate and its key can remain usable until the certificate expires.",
    # existing_connections: graceful_dedicated_connections.
    "Existing SSH connections may stay open at expiry, and detached remote work can keep running.",
    # The page's note on this check.
    "It checks the guarantee table and the known limits word for word.",
    "It also holds every sentence about revocation, expiry or a guarantee to reviewed wording.",
    # Support descriptions.
    "**Verified** enrollment, new logins and expiry with a test build.",
    "**Verified** enrollment, new logins and expiry on a headless host.",
    "**Verified** enrollment, new logins and strict expiry with the inbox OpenSSH client.",
}


class MatrixRow(NamedTuple):
    label: str
    setup: str  # The row's environment, client, signer and mechanism cells.
    statuses: frozenset  # Of "verified" and "blocked": what the row's evidence cell reports.


def tables(markdown):
    for match in TABLE.finditer(markdown):
        header, *body = match[0].splitlines()
        columns = tuple(cell.strip() for cell in header.strip()[1:-1].split("|"))
        if body and re.fullmatch(r"\|(?:\s*:?-{3,}:?\s*\|)+", body[0].strip()):
            rows = [tuple(cell.strip() for cell in line.strip()[1:-1].split("|")) for line in body[1:]]
            yield columns, rows


def matrix_rows(matrix):
    found = {}
    for columns, rows in tables(matrix):
        if columns[0] == "#" and "Label" in columns:
            label = columns.index("Label")
            if "evidence" not in " ".join(columns[label + 1:label + 2]).lower():
                raise ValueError("compatibility matrix: no evidence column after Label")
            for row in rows:
                if len(row) != len(columns) or row[0] in found:
                    raise ValueError("malformed or duplicate compatibility matrix row")
                # An evidence cell reports a status at its start and after each semicolon.
                statuses = re.findall(r"(?:^|;\s*)(verified|blocked)\b", row[label + 1])
                found[row[0]] = MatrixRow(row[label].strip("`"), " | ".join(row[1:label]), frozenset(statuses))
    return found


def version_range(bounds):
    if bounds["min"] == bounds["max"]:
        return bounds["min"]
    return f'{bounds["min"]}–{bounds["max"]}' if bounds["max"] else f'{bounds["min"]} and later'


def residual_digest(entry):
    return hashlib.sha256(f'{entry["limits"]}\n{entry["description"]}'.encode("utf-8")).hexdigest()[:16]


def sentences(text):
    """The visible sentences: each heading whole, each paragraph split after `.`, `!` or `?`."""
    text = re.sub(r"(?s)<!--.*?-->", " ", text)
    text = re.sub(r"(?m)^(#+ .*)$", r"\n\1\n", text)
    for block in re.split(r"\n[ \t]*\n", text):
        yield from filter(None, re.split(r"(?<=[.!?])\s+", " ".join(block.split())))


def check_support(setup, label, tested, cited, matrix):
    if setup not in SETUPS:
        raise ValueError(f"{setup}: no fixed evidence mapping for this setup")
    expected = [row for _, rows in SETUPS[setup] for row in rows.split()]
    if cited.split(", ") != expected:
        raise ValueError(f"{setup}: matrix rows must be exactly {', '.join(expected)}")
    statuses = set()
    for words, rows in SETUPS[setup]:
        for row in rows.split():
            if row not in matrix:
                raise ValueError(f"{setup}: unknown matrix row {row}")
            if words.lower() not in matrix[row].setup.lower():
                raise ValueError(f"{setup}: matrix row {row} no longer describes this setup ({words})")
            if label != matrix[row].label:
                raise ValueError(f"{setup}: support label {label} differs from matrix row {row} ({matrix[row].label})")
            statuses |= matrix[row].statuses
    bold = re.findall(r"(?i)\*\*(verified|blocked)\*\*", tested)
    if len(bold) != len(re.findall(r"(?i)\b(?:verified|blocked)\b", tested)):
        raise ValueError(f"{setup}: verified and blocked must be bold status words")
    if {word.lower() for word in bold} != statuses:
        raise ValueError(
            f"{setup}: status words ({', '.join(sorted({word.lower() for word in bold})) or 'none'}) differ from "
            f"the evidence of its matrix rows ({', '.join(sorted(statuses)) or 'none'})"
        )


def check_page(page, matrix, claims, residuals):
    sections = {SUPPORT: [], GUARANTEES: [], LIMITS: []}
    blocks = 0
    for columns, rows in tables(page):
        blocks += 1
        if columns not in sections:
            raise ValueError(f"unexpected table: {columns[0]}")
        if not rows or any(len(row) != len(columns) or not all(row) for row in rows):
            raise ValueError(f"malformed adapter table: {columns[0]}")
        sections[columns].append(rows)
    if blocks != len(TABLE.findall(page)):
        raise ValueError("a block of `|` lines is not a table")
    if [len(sections[columns]) for columns in (SUPPORT, GUARANTEES, LIMITS)] != [3, 1, 1]:
        raise ValueError("expected three support tables, one guarantee table and one known-limits table")

    support = [row for rows in sections[SUPPORT] for row in rows]
    for row in support:
        check_support(*row, matrix)
    if sorted(row[0] for row in support) != sorted(SETUPS):
        raise ValueError("the support tables must list each setup in SETUPS once")

    allowed = {
        (claim["platform"]["os"], claim["platform"]["arch"], claim["os_floor"],
         version_range(claim["client_versions"]), version_range(claim["signer_builds"]),
         claim["build_profile"], claim["store_kind"], claim["field"], claim["value"])
        for claim in claims
    }
    for platform, floor, client, signer, profile, behavior in sections[GUARANTEES][0]:
        if platform not in PLATFORMS:
            raise ValueError(f"guarantee for a platform without a native claim row: {platform}")
        for sentence in re.split(r"(?<=\.) +", behavior):
            keys = BEHAVIORS.get(sentence)
            if not keys or any(
                (*PLATFORMS[platform], floor, client, signer, profile, None, field, value) not in allowed
                for field, value in keys
            ):
                raise ValueError(f"{platform}: guarantee outside CLAIMS or its version bounds: {sentence}")

    # The guide covers access and signing. Purge and uninstall-only operations are outside its scope.
    required = {
        entry["id"]: entry for entry in residuals
        if not entry["limits"].startswith("uninstall.") or entry["id"].startswith("issuer_")
    }
    documented = set()
    for where, limit in sections[LIMITS][0]:
        match = re.fullmatch(r"([^<>]+?)\s+<!-- ([a-z0-9_]+) -->", limit)
        if not match or not match[1].strip():
            raise ValueError("each known limit needs visible text and one residual ID")
        if match[2] in documented:
            raise ValueError(f"duplicate known limit: {match[2]}")
        documented.add(match[2])
        if match[2] not in required:
            continue  # Reported below.
        if match[2] not in KNOWN_LIMITS:
            raise ValueError(f"known limit {match[2]} has no reviewed wording in KNOWN_LIMITS")
        reviewed_where, reviewed, digest = KNOWN_LIMITS[match[2]]
        if (where, match[1]) != (reviewed_where, reviewed):
            raise ValueError(f"known limit {match[2]} differs from its reviewed wording")
        if residual_digest(required[match[2]]) != digest:
            raise ValueError(
                f"known limit {match[2]}: its RESIDUALS entry changed after the wording was reviewed. Read the "
                f"sentence against the entry, then record digest {residual_digest(required[match[2]])}"
            )
    if required.keys() - documented:
        raise ValueError("missing known limits: " + ", ".join(sorted(required.keys() - documented)))
    if documented - required.keys():
        raise ValueError("unexpected known limits: " + ", ".join(sorted(documented - required.keys())))

    prose = [TABLE.sub("\n", page), *(tested for _, _, tested, _ in support)]
    for sentence in (sentence for text in prose for sentence in sentences(text)):
        if GUARDED.search(sentence) and sentence not in REVIEWED:
            raise ValueError(
                "a sentence about revocation, expiry or a guarantee, or with a universal word, is not reviewed "
                f"wording: {sentence}"
            )


def self_check(page, matrix, claims, residuals):
    first_rows = {columns: rows[0] for columns, rows in tables(page) if columns in (GUARANTEES, LIMITS)}
    guarantee, limit = first_rows[GUARANTEES], first_rows[LIMITS]
    # A support row with both statuses, so a changed status word still leaves the other one.
    support = next(
        row for columns, rows in tables(page) if columns == SUPPORT
        for row in rows if "**Verified**" in row[2] and "**blocked**" in row[2]
    )
    cited = support[3].split(", ")

    def replace(row, updated):
        original = "| " + " | ".join(row) + " |\n"
        replacement = "| " + " | ".join(updated) + " |\n" if updated else ""
        return page.replace(original, replacement, 1)

    wrong_label = "not-tested" if support[1] == "verified" else "verified"
    limit_marker = "<!-- " + limit[1].split("<!-- ", 1)[1]
    # A row of another setup with the same label and the same statuses: only the fixed mapping tells them apart.
    statuses = set().union(*(matrix[row].statuses for row in cited))
    stand_in = next(
        row for row, entry in sorted(matrix.items())
        if row not in cited and entry.label == support[1] and entry.statuses == statuses
    )
    reviewed = KNOWN_LIMITS[limit_marker[5:-4]][1]
    moved = {**matrix, cited[0]: matrix[cited[0]]._replace(setup="another setup")}
    edited = [{**entry, "description": entry["description"] + " More."} for entry in residuals]
    universal = "Revocation takes effect immediately on every machine."
    cases = (
        (replace(guarantee, (*guarantee[:2], "all OpenSSH versions", *guarantee[3:])), "outside CLAIMS"),
        (replace(guarantee, (*guarantee[:-1], "Every remote process stops on expiry.")), "outside CLAIMS"),
        (replace(guarantee, ("WSL2 Mode B", *guarantee[1:])), "without a native claim row"),
        (replace(support, (support[0], wrong_label, *support[2:])), "differs from matrix"),
        (replace(limit, ()), "missing known limits"),
        (replace(limit, (limit[0], limit_marker)), "needs visible text"),
        # ⟨M07-W1-R06⟩ The four mutations of the W1 review.
        (replace(support, (*support[:2], support[2].replace("**blocked**", "**verified**"), support[3])),
         "status words"),
        (replace(support, (*support[:3], stand_in)), "matrix rows must be exactly"),
        (page.replace(reviewed, reviewed.replace(" can ", " cannot ", 1), 1), "differs from its reviewed wording"),
        (page + "\n" + universal + "\n", "not reviewed wording"),
        # The same claim in a support description, in a table of its own, and in a stray `|` line.
        (replace(support, (*support[:2], support[2] + " " + universal, support[3])), "not reviewed wording"),
        (page + "\n| Claim |\n|---|\n| " + universal + " |\n", "unexpected table"),
        (page + "\n| " + universal + " |\n", "is not a table"),
        # A status word that is not bold, and a setup without a mapping.
        (replace(support, (*support[:2], support[2] + " Also verified elsewhere.", support[3])), "must be bold"),
        (replace(support, ("Another setup", *support[1:])), "no fixed evidence mapping"),
    )
    # The sources drift under an unchanged page: a matrix row describes another setup, and a
    # residual's text changes after its sentence was reviewed.
    drifted = ((moved, residuals, "no longer describes"), (matrix, edited, "changed after the wording was reviewed"))
    runs = [(mutant, matrix, residuals, expected) for mutant, expected in cases]
    runs += [(page, *sources) for sources in drifted]
    for mutant, mutant_matrix, mutant_residuals, expected in runs:
        try:
            check_page(mutant, mutant_matrix, claims, mutant_residuals)
        except ValueError as exc:
            if expected in str(exc):
                continue
            raise
        raise ValueError(f"self-check accepted an invalid page, expected: {expected}")
    print(f"adapter page: self-checks OK ({len(runs)} invalid pages or sources rejected)")


def main():
    # Isolated Python ignores PYTHONDONTWRITEBYTECODE, including for claims_table's imports.
    sys.dont_write_bytecode = True
    parser = runpy.run_path(str(Path(__file__).with_name("claims_table.py")))
    try:
        source = (ROOT / "crates/domain/src/claims.rs").read_text(encoding="utf-8")
        claims, _, _ = parser["parse_claims"](source)
        residuals = parser["parse_residuals"](source)
        matrix = matrix_rows((ROOT / "docs/compatibility/matrix.md").read_text(encoding="utf-8"))
        page = (ROOT / "docs/user/adapters.md").read_text(encoding="utf-8")
        check_page(page, matrix, claims, residuals)
        self_check(page, matrix, claims, residuals)
    except (OSError, ValueError, parser["ParseError"]) as exc:
        print(f"adapter page: FAIL: {exc}", file=sys.stderr)
        return 1
    print("adapter page: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
