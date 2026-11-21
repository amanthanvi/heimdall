#!/usr/bin/env python3
"""Check the adapter guide's support labels, native guarantees and known limits."""

import re
import runpy
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
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


def tables(markdown):
    for match in re.finditer(r"(?m)(?:^\|[^\n]*\|[ \t]*(?:\n|$))+", markdown):
        header, *body = match[0].splitlines()
        columns = tuple(cell.strip() for cell in header.strip()[1:-1].split("|"))
        if body and re.fullmatch(r"\|(?:\s*:?-{3,}:?\s*\|)+", body[0].strip()):
            rows = [tuple(cell.strip() for cell in line.strip()[1:-1].split("|")) for line in body[1:]]
            yield columns, rows


def matrix_labels(matrix):
    labels = {}
    for columns, rows in tables(matrix):
        if columns[0] == "#" and "Label" in columns:
            label_column = columns.index("Label")
            for row in rows:
                if len(row) != len(columns) or row[0] in labels:
                    raise ValueError("malformed or duplicate compatibility matrix row")
                labels[row[0]] = row[label_column].strip("`")
    return labels


def version_range(bounds):
    if bounds["min"] == bounds["max"]:
        return bounds["min"]
    return f'{bounds["min"]}–{bounds["max"]}' if bounds["max"] else f'{bounds["min"]} and later'


def check_page(page, labels, claims, residuals):
    sections = {SUPPORT: [], GUARANTEES: [], LIMITS: []}
    for columns, rows in tables(page):
        if columns in sections:
            if not rows or any(len(row) != len(columns) or not all(row) for row in rows):
                raise ValueError(f"malformed adapter table: {columns[0]}")
            sections[columns].append(rows)
    if [len(sections[columns]) for columns in (SUPPORT, GUARANTEES, LIMITS)] != [3, 1, 1]:
        raise ValueError("expected three support tables, one guarantee table and one known-limits table")

    for rows in sections[SUPPORT]:
        for setup, label, _, sources in rows:
            for source in sources.split(", "):
                if source not in labels:
                    raise ValueError(f"{setup}: unknown matrix row {source}")
                if label != labels[source]:
                    raise ValueError(
                        f"{setup}: support label {label} differs from matrix row {source} ({labels[source]})"
                    )

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
        entry["id"] for entry in residuals
        if not entry["limits"].startswith("uninstall.") or entry["id"].startswith("issuer_")
    }
    documented = set()
    for _, limit in sections[LIMITS][0]:
        match = re.fullmatch(r"([^<>]+?)\s+<!-- ([a-z0-9_]+) -->", limit)
        if not match or not match[1].strip():
            raise ValueError("each known limit needs visible text and one residual ID")
        if match[2] in documented:
            raise ValueError(f"duplicate known limit: {match[2]}")
        documented.add(match[2])
    if required - documented:
        raise ValueError("missing known limits: " + ", ".join(sorted(required - documented)))
    if documented - required:
        raise ValueError("unexpected known limits: " + ", ".join(sorted(documented - required)))


def self_check(page, labels, claims, residuals):
    first_rows = {
        columns: rows[0] for columns, rows in tables(page) if columns in (SUPPORT, GUARANTEES, LIMITS)
    }
    support, guarantee, limit = (first_rows[columns] for columns in (SUPPORT, GUARANTEES, LIMITS))

    def replace(row, updated):
        original = "| " + " | ".join(row) + " |\n"
        replacement = "| " + " | ".join(updated) + " |\n" if updated else ""
        return page.replace(original, replacement, 1)

    wrong_label = "not-tested" if support[1] == "verified" else "verified"
    limit_marker = "<!-- " + limit[1].split("<!-- ", 1)[1]
    cases = (
        (replace(guarantee, (*guarantee[:2], "all OpenSSH versions", *guarantee[3:])), "outside CLAIMS"),
        (replace(guarantee, (*guarantee[:-1], "Every remote process stops on expiry.")), "outside CLAIMS"),
        (replace(guarantee, ("WSL2 Mode B", *guarantee[1:])), "without a native claim row"),
        (replace(support, (support[0], wrong_label, *support[2:])), "differs from matrix"),
        (replace(limit, ()), "missing known limits"),
        (replace(limit, (limit[0], limit_marker)), "needs visible text"),
    )
    for mutant, expected in cases:
        try:
            check_page(mutant, labels, claims, residuals)
        except ValueError as exc:
            if expected in str(exc):
                continue
            raise
        raise ValueError(f"self-check accepted an invalid page, expected: {expected}")
    print(f"adapter page: self-checks OK ({len(cases)} invalid pages rejected)")


def main():
    # Isolated Python ignores PYTHONDONTWRITEBYTECODE, including for claims_table's imports.
    sys.dont_write_bytecode = True
    parser = runpy.run_path(str(Path(__file__).with_name("claims_table.py")))
    try:
        source = (ROOT / "crates/domain/src/claims.rs").read_text(encoding="utf-8")
        claims, _, _ = parser["parse_claims"](source)
        residuals = parser["parse_residuals"](source)
        labels = matrix_labels((ROOT / "docs/compatibility/matrix.md").read_text(encoding="utf-8"))
        page = (ROOT / "docs/user/adapters.md").read_text(encoding="utf-8")
        check_page(page, labels, claims, residuals)
        self_check(page, labels, claims, residuals)
    except (OSError, ValueError, parser["ParseError"]) as exc:
        print(f"adapter page: FAIL: {exc}", file=sys.stderr)
        return 1
    print("adapter page: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
