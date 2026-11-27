#!/usr/bin/env python3
"""Generate and check the U7b compatibility matrix. See matrix-rows.json and README.md."""
import argparse
import json
from pathlib import Path
import re
import runpy
import tempfile

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs/compatibility/matrix.md"
PACKAGE = ROOT / "tools/packaging/compatibility-matrix.md"
ROWS = Path(__file__).with_name("matrix-rows.json")
EVIDENCE = ROOT / "tests/evidence"
SCHEMA = EVIDENCE / "record.schema.json"
LIMITS = ROOT / "docs/user/limitations.md"
BEGIN = "<!-- BEGIN GENERATED COMPATIBILITY MATRIX -->"
END = "<!-- END GENERATED COMPATIBILITY MATRIX -->"
PLACEHOLDER = "<!-- HEIMDALL-COMPATIBILITY-MATRIX-PLACEHOLDER -->"
PACKAGE_TITLE = "# Compatibility matrix\n\n"
CANDIDATE = re.compile(r"[0-9a-f]{40}")
RECORD_ID = re.compile(r"[a-z0-9][a-z0-9-]*\.json")
LABELS = {"verified", "supported-with-limitations", "experimental", "unsupported", "not-tested"}
STATUSES = ("blocked", "not_started", "in_progress", "implemented_unverified", "verified")
COLUMNS = (
    "#", "Environment", "Client", "Provider / signer", "Mechanism", "Label",
    "Gate evidence", "Versions and record start", "Record", "Limitation",
)
HEADER = "| " + " | ".join(COLUMNS) + " |"
SEPARATOR = "| " + " | ".join(["---"] * len(COLUMNS)) + " |"
VALIDATOR = runpy.run_path(str(ROOT / "tests/g02/minischema.py"))


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


class Records:
    def __init__(self, directory):
        self.directory = directory
        self.schema = read_json(SCHEMA)
        self.cache = {}

    def get(self, name):
        if not RECORD_ID.fullmatch(name):
            raise ValueError("invalid record ID")
        if name not in self.cache:
            path = self.directory / name
            if not path.is_file():
                raise ValueError(f"{name}: missing evidence record")
            record = read_json(path)
            if VALIDATOR["validate"](self.schema, record):
                raise ValueError(f"{name}: fails record.schema.json")
            self.cache[name] = record
        return self.cache[name]


def selected_subrow(record, prefix):
    """Select one observed platform row, never the first of several matches."""
    observed = record["observed_result"]
    rows = observed.get("rows", []) if isinstance(observed, dict) else []
    matches = [
        row for row in rows
        if isinstance(row.get("platform"), str) and row["platform"].startswith(prefix)
    ]
    if len(matches) != 1:
        raise ValueError("platform selector must match exactly one observed row")
    return matches[0]


def version_values(record, prefixes):
    for entry in record["provider_versions"]:
        if isinstance(entry, str) and any(entry.startswith(prefix) for prefix in prefixes):
            yield entry
        elif isinstance(entry, dict):
            name, version = entry.get("name"), entry.get("version")
            if (isinstance(name, str) and isinstance(version, str)
                    and any(name.startswith(prefix) for prefix in prefixes)):
                yield version


def documented_limit(document, heading):
    # Use one named, top-level bullet. A removed or ambiguous source fails the check.
    blocks = re.split(r"(?m)^- ", document)[1:]
    matches = [block for block in blocks if block.startswith(f"**{heading}")]
    if len(matches) != 1:
        raise ValueError(f"one limitations.md bullet must begin with {heading!r}")
    excerpt = matches[0].split("\n\n", 1)[0].strip()
    return f"{excerpt} (`docs/user/limitations.md`)"


def evidence_fields(row, records, limits, candidate):
    bindings = row.get("candidate" if candidate else "draft", [])
    names, statuses, versions, dates, excerpts = [], [], [], [], []
    for binding in bindings:
        name = binding["record"]
        record = records.get(name)
        if candidate and record["build_commit"] != candidate:
            raise ValueError(f"{name}: build_commit differs from candidate {candidate}")
        names.append(name)
        selected = selected_subrow(record, binding["platform"]) if "platform" in binding else record
        status = selected["status"]
        if status not in (*STATUSES, "deferred_with_decision"):
            raise ValueError(f"{name}: unknown evidence status")
        statuses.append(status)
        if "versions" in binding:
            versions.extend(version_values(record, binding["versions"]))
        if record["started_at"]:
            dates.append(record["started_at"])
        if "limitation" in binding:
            index = binding["limitation"]
            if not 0 <= index < len(record["limitations"]):
                raise ValueError(f"{name}: missing declared limitations entry")
            excerpts.append(f"{record['limitations'][index]} (`{name}`)")
        if selected.get("blocked_on"):
            excerpts.append(f"{selected['blocked_on']} (`{name}`)")

    # Historical notes can cite supporting records without making their aggregate
    # platform statuses count for the combination in this row.
    if not candidate:
        for name in row.get("historical_records", []):
            records.get(name)
            names.append(name)

    active = [status for status in statuses if status != "deferred_with_decision"]
    if active:
        status = min(active, key=STATUSES.index)
    elif statuses:
        status = "deferred_with_decision"
    else:
        status = "not_started"

    # Baseline gate and plan gaps can describe missing inputs without an evidence
    # record. They never supply the product-support label.
    gate = status
    if not candidate:
        gate = row.get("draft_gate", "; ".join(dict.fromkeys(statuses)) or status)
    if not statuses and row.get("pending"):
        gate = row["pending"]

    label = row.get("candidate_label", "not-tested") if candidate else "not-tested"
    if label in {"verified", "supported-with-limitations"} and (
        not statuses or any(status != "verified" for status in statuses)
    ):
        raise ValueError("claimed support needs verified evidence for this combination")
    if not excerpts:
        heading = row.get("limit", "What was not run before this release:")
        excerpts.append(documented_limit(limits, heading))
    # Historical pins and stated versions live in the repo's notes. The generated
    # versions column reports only the selected observations.
    version_text = "; ".join(dict.fromkeys(versions)) or "—"
    if dates:
        version_text += " / Record started " + ", ".join(dict.fromkeys(dates))
    return label, gate, version_text, ", ".join(f"`{name}`" for name in dict.fromkeys(names)) or "—", (
        "<br>".join(dict.fromkeys(excerpts))
    )


def markdown_cell(value):
    return " ".join(value.splitlines()).replace("|", "&#124;")


def render(rows, records, limits, candidate=None):
    state = f"Candidate build: `{candidate}`." if candidate else (
        "Draft generated from the available evidence records. Historical gate evidence "
        "does not set a release support label."
    )
    lines = [
        BEGIN, "", "## Provider × client × environment × mechanism", "", state, "",
        "Labels use spec §3.3. Gate evidence is the status of the selected observation "
        "or a documented gap. Clean-machine and fresh-account rows are separate (M08 plan §4).",
        "", HEADER, SEPARATOR,
    ]
    for row in rows:
        try:
            fields = evidence_fields(row, records, limits, candidate)
        except ValueError as exc:
            raise ValueError(f"{row['id']}: {exc}") from exc
        cells = [row[key] for key in ("id", "environment", "client", "provider", "mechanism")]
        lines.append("| " + " | ".join(map(markdown_cell, (*cells, *fields))) + " |")
    return "\n".join([*lines, "", END])


def generated_parts(markdown):
    before, begin, rest = markdown.partition(BEGIN)
    body, end, after = rest.partition(END)
    if not begin or not end or BEGIN in body + after or END in before + after:
        raise ValueError("expected exactly one generated matrix block")
    return before, begin + body + end, after


def matrix_rows_cite_existing_records(markdown, records, candidate=None):
    """Validate the generated Markdown itself, including all actual record citations."""
    _, generated, _ = generated_parts(markdown)
    lines = generated.splitlines()
    if HEADER not in lines or lines.count(HEADER) != 1:
        raise ValueError("missing or repeated generated table header")
    table = lines[lines.index(HEADER):]
    if len(table) < 5:
        raise ValueError("malformed or empty generated table")
    _, separator, *rows = table
    if separator != SEPARATOR or rows[-2:] != ["", END] or len(rows) == 2:
        raise ValueError("malformed or empty generated table")

    seen = set()
    for line in rows[:-2]:
        cells = line.split("|")
        if (len(cells) != len(COLUMNS) + 2 or cells[0] or cells[-1]
                or not all(cell.strip() for cell in cells[1:-1])):
            raise ValueError("malformed generated table row")
        row, _, _, _, _, label, _, _, cited, _ = (cell.strip() for cell in cells[1:-1])
        if row in seen:
            raise ValueError(f"{row}: duplicate row")
        seen.add(row)
        if label not in LABELS:
            raise ValueError(f"{row}: unknown support label")
        if cited == "—":
            if label != "not-tested":
                raise ValueError(f"{row}: {label} requires an evidence record")
            continue
        for citation in cited.split(", "):
            if not re.fullmatch(r"`[a-z0-9][a-z0-9-]*\.json`", citation):
                raise ValueError(f"{row}: malformed record citation")
            name = citation[1:-1]
            record = records.get(name)
            if candidate and record["build_commit"] != candidate:
                raise ValueError(f"{row}: {name} build_commit differs from candidate {candidate}")
    return len(seen)


def self_test():
    sha = "a" * 40
    fixture = {
        "case_id": "A31", "status": "verified", "requirement_ids": [],
        "build_commit": sha, "artifact_digest": None, "environment": "fixture",
        "provider_versions": ["fixture ssh 9.6"], "started_at": "2026-11-26T12:00:00Z",
        "commands_or_harness": "fixture", "observed_result": "fixture result",
        "evidence_paths": [], "limitations": ["fixture limitation"],
    }
    row = "| SAMPLE | Fixture OS | SSH | Agent | Sign | verified | verified | SSH 9.6 | `{}.json` | Fixture limit |"
    with tempfile.TemporaryDirectory(prefix="heimdall-matrix-") as directory:
        root = Path(directory)
        for name, record in {
            "valid": fixture,
            "invalid": dict(fixture, provider_versions="unstructured"),
            "old-build": dict(fixture, build_commit="b" * 40),
        }.items():
            (root / f"{name}.json").write_text(json.dumps(record), encoding="utf-8")
        records = Records(root)
        for name, error in (
            ("missing", "missing evidence record"),
            ("invalid", "fails record.schema.json"),
            ("old-build", "build_commit differs"),
            ("valid", None),
        ):
            markdown = "\n".join([BEGIN, HEADER, SEPARATOR, row.format(name), "", END])
            try:
                count = matrix_rows_cite_existing_records(markdown, records, sha)
            except ValueError as exc:
                if not error or error not in str(exc):
                    raise ValueError(f"self-test {name}: {exc}") from exc
            else:
                if error or count != 1:
                    raise ValueError(f"self-test {name}: unexpected acceptance")
    print("matrix_rows_cite_existing_records self-test: 4 cases, 0 failed")


def check_file(path, markdown, expected, records, candidate=None):
    matrix_rows_cite_existing_records(markdown, records, candidate)
    if markdown != expected:
        command = "matrix.py --write" + (f" --candidate {candidate}" if candidate else "")
        raise ValueError(f"{path.name}: generated matrix is stale; run {command}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true", help="regenerate the draft or candidate")
    action.add_argument("--check", action="store_true", help="verify the checked-in matrix")
    action.add_argument("--self-test", action="store_true", help="run only the fixture tests")
    parser.add_argument("--candidate", metavar="SHA", help="finalize or check the packaged slot for a full build SHA")
    args = parser.parse_args()
    if args.candidate and (args.self_test or not CANDIDATE.fullmatch(args.candidate)):
        parser.error("--candidate requires a full lowercase commit SHA with --write or --check")

    try:
        if args.check or args.self_test:
            self_test()
        if args.self_test:
            return 0

        records = Records(EVIDENCE)
        rows = read_json(ROWS)
        limits = LIMITS.read_text(encoding="utf-8")
        if not args.candidate:
            draft = render(rows, records, limits)
            doc = DOC.read_text(encoding="utf-8")
            before, _, after = generated_parts(doc)
            expected_doc = before + draft + after
            matrix_rows_cite_existing_records(expected_doc, records)
            if args.write:
                DOC.write_text(expected_doc, encoding="utf-8")
            else:
                check_file(DOC, doc, expected_doc, records)

        candidate = args.candidate
        package = PACKAGE.read_text(encoding="utf-8") if args.check else ""
        if args.check and not candidate and not package.startswith(PLACEHOLDER):
            _, body, _ = generated_parts(package)
            match = re.search(r"(?m)^Candidate build: `([0-9a-f]{40})`\.$", body)
            if not match:
                raise ValueError("packaged matrix needs the draft placeholder or a candidate build")
            candidate = match[1]
        if candidate:
            if PLACEHOLDER in package:
                raise ValueError(f"{PACKAGE.name}: candidate matrix still has its placeholder")
            if not any(row.get("candidate") for row in rows):
                raise ValueError("bind the candidate's exit records in matrix-rows.json before finalizing")
            body = render(rows, records, limits, candidate)
            expected_package = PACKAGE_TITLE + body + "\n"
        else:
            expected_package = PLACEHOLDER + "\n" + PACKAGE_TITLE + draft + "\n"
        count = matrix_rows_cite_existing_records(expected_package, records, candidate)
        if args.write:
            PACKAGE.write_text(expected_package, encoding="utf-8")
        else:
            check_file(PACKAGE, package, expected_package, records, candidate)
        print(f"matrix_rows_cite_existing_records: {count} rows ({'candidate' if candidate else 'draft'})")
        return 0
    except (OSError, ValueError, KeyError, TypeError, VALIDATOR["SchemaUnsupported"]) as exc:
        print(f"matrix_rows_cite_existing_records: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
