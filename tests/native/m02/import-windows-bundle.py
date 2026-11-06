#!/usr/bin/env python3
"""Import a Windows local-mode results bundle (run-windows-local.ps1; ADR-0007 §12.32 item 17)
into tests/evidence/artifacts/m02/<label>/windows/ and feed it to the evidence generator.

Usage (from the repository root, with `python3 -I`):
  import-windows-bundle.py --bundle REPORT --label LABEL [--config RUNS.json] [--commit HEX]
                           [--artifacts-root DIR]

REPORT is any text that contains the bundle between its BEGIN and END markers (the local
agent's report, or bundle.b64 itself). The import:
  * decodes the gzip+base64 payload and checks its sha256 line, the bundle format, the commit
    (40 hexadecimal digits; with --commit, exactly that one) and every file's sha256;
  * accepts exactly the result files the runner writes (no path, no other name);
  * refuses a bundle that still carries a canary prefix, an unmasked user or domain SID, or a
    non-loopback IPv4 address (the runner redacts and masks those before anything leaves the
    PC; their presence is a defect, so nothing is written);
  * checks that the files are what m02-evidence.py reads: tests.txt has at least one
    "### <target>" result and its exit line, commands.txt has "exit N: ..." lines and host.txt
    has key=value facts;
  * writes them into <artifacts-root>/<label>/windows/ (default artifacts root
    tests/evidence/artifacts/m02), created exclusively: an existing, non-empty directory is
    never overwritten;
  * with --config, points that run configuration's `windows` platform at the files (logs,
    commands_logs, facts, the bundle's label and artifact digest) and drops its
    `unavailable` mark, so `m02-evidence.py --config RUNS.json` reads them.
Exit: 0 on success, 1 when the bundle is refused (nothing written), 2 for a usage error.
"""

import argparse
import base64
import hashlib
import importlib.util
import json
import re
import sys
import zlib
from pathlib import Path

FORMAT = "heimdall-m02-windows-local-bundle/1"
BEGIN = "-----BEGIN HEIMDALL M02 WINDOWS BUNDLE-----"
END = "-----END HEIMDALL M02 WINDOWS BUNDLE-----"
FILES = ("tests.txt", "commands.txt", "host.txt", "build.txt", "skipped.txt", "canary-scan.txt")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MAX_PAYLOAD = 64 * 1024 * 1024
# ADR-0007 §12.35 item 3 (N04): every size is bounded before it is read whole. The compressed
# payload may be at most MAX_PAYLOAD (gzip never needs more for this content), its base64 at most
# 4/3 of that plus line breaks, and the report around it at most twice that.
MAX_COMPRESSED = MAX_PAYLOAD
MAX_BASE64 = (MAX_COMPRESSED + 2) // 3 * 4 + MAX_COMPRESSED // 57 + 1024
MAX_REPORT = 2 * MAX_BASE64
MAX_LABEL = 200

# ADR-0007 §12.35 item 3 (N03): content that must never leave the PC, checked in every file body
# and in every metadata field that is persisted. The runner redacts and masks these before the
# bundle is written; their presence is a defect, so nothing is imported.
_SENSITIVE = (
    (re.compile(r"HEIMDALL_CANARY_"), "a canary prefix"),
    (re.compile(r"S-1-(5-21|12-1)-\d"), "an unmasked user or domain SID"),
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"), "private-key armor"),
    # ADR-0007 §12.38 item 3 (L03): only an exact system profile component is exempt (followed
    # by a separator, a quote, whitespace or the end), never a personal name that starts with it.
    (re.compile(r"(?i)\b[A-Z]:[\\/]+Users[\\/]+(?!<|(?:Public|Default|Default User|All Users)(?=[\\/\s\"'<>]|$))[^\\/\s\"'<>]+"),
     "an unredacted Windows home path"),
    (re.compile(r"(?i)/mnt/[a-z]/Users/(?!<|(?:Public|Default|Default User|All Users)(?=[/\s\"'<>]|$))[^/\s\"'<>]+"),
     "an unredacted Windows home path"),
    (re.compile(r"(?<![\w/.-])/home/(?!<)[A-Za-z0-9._-]+"), "an unredacted Unix home path"),
    # The macOS form never follows a drive letter's colon: C:/Users/... is the Windows rule's.
    (re.compile(r"(?<![\w/.:-])/Users/(?!<|Shared(?=[/\s\"'<>]|$))[A-Za-z0-9._-]+"), "an unredacted macOS home path"),
)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")


def sensitive(text):
    """The reason `text` must not be imported, or None."""
    for rx, why in _SENSITIVE:
        if rx.search(text):
            return why
    for m in _IPV4.finditer(text):
        if not (m.group(0).startswith("127.") or m.group(0) == "0.0.0.0"):
            return "a non-loopback IPv4 address"
    return None


class Refused(Exception):
    """The bundle is not imported."""


def load_generator():
    spec = importlib.util.spec_from_file_location("m02_evidence", HERE / "m02-evidence.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def decode(text):
    """The bundle document from a report that contains it between the markers."""
    if len(text) > MAX_REPORT:
        raise Refused("the report is larger than the bundle bound")
    start = text.find(BEGIN)
    end = text.find(END, start + 1 if start >= 0 else 0)
    if start < 0 or end < 0:
        raise Refused("no bundle between the BEGIN and END markers")
    if text.find(BEGIN, start + 1) >= 0 and text.find(BEGIN, start + 1) < end:
        raise Refused("a second BEGIN marker before the END marker")
    lines = [l.strip() for l in text[start + len(BEGIN):end].splitlines() if l.strip()]
    if not lines or not lines[0].startswith("sha256-gzip: "):
        raise Refused("the payload's sha256 line is missing")
    want = lines[0][len("sha256-gzip: "):].strip().lower()
    body = "".join(lines[1:])
    if len(body) > MAX_BASE64:
        raise Refused("the base64 payload is larger than its bound")
    if not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", body):
        raise Refused("the payload is not base64")
    packed = base64.b64decode(body, validate=True)
    if len(packed) > MAX_COMPRESSED:
        raise Refused("the compressed payload is larger than its bound")
    if hashlib.sha256(packed).hexdigest() != want:
        raise Refused("the payload's sha256 does not match")
    # Incremental: never more than MAX_PAYLOAD + 1 bytes are produced.
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        raw = inflater.decompress(packed, MAX_PAYLOAD + 1)
    except zlib.error as e:
        raise Refused(f"the payload is not gzip: {e}") from None
    if len(raw) > MAX_PAYLOAD or inflater.unconsumed_tail:
        raise Refused("the payload is larger than 64 MiB")
    if not inflater.eof:
        raise Refused("the payload is not a complete gzip stream")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise Refused(f"the payload is not UTF-8 JSON: {e}") from None
    return doc


def validate(doc, commit=None):
    """The checked files {name: text} of a decoded bundle."""
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise Refused(f"not a {FORMAT} bundle")
    c = doc.get("commit")
    if not isinstance(c, str) or not re.fullmatch(r"[0-9a-f]{40}", c):
        raise Refused("the bundle names no 40-hex commit")
    if commit and c != commit:
        raise Refused("the bundle is for another commit")
    label = doc.get("label", "")
    if not isinstance(label, str) or len(label) > MAX_LABEL or not label.isprintable():
        raise Refused("the bundle's label is not a short printable string")
    why = sensitive(label)
    if why:
        raise Refused(f"the bundle's label carries {why}")
    files, sums = doc.get("files"), doc.get("sha256")
    if not isinstance(files, dict) or not isinstance(sums, dict):
        raise Refused("the bundle has no files")
    if set(files) != set(FILES) or set(sums) != set(FILES):
        raise Refused("the bundle's files are not exactly the result files")
    out = {}
    for name in FILES:
        text = files[name]
        if not isinstance(text, str):
            raise Refused(f"{name} is not text")
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != str(sums[name]).lower():
            raise Refused(f"{name}: sha256 does not match")
        why = sensitive(text)
        if why:
            raise Refused(f"{name} carries {why}")
        out[name] = text
    return out


def check_readable(ev, directory):
    """The imported files read as the generator reads them."""
    logs = ev.parse_log(directory / "tests.txt")
    if not logs or not any(logs.values()):
        raise Refused("tests.txt has no test results the generator reads")
    if not re.search(r"(?m)^### [A-Za-z0-9_-]+ exit=-?\d+$", (directory / "tests.txt").read_text(encoding="utf-8")):
        raise Refused("tests.txt has no '### <target> exit=N' line")
    if not ev.parse_commands(directory / "commands.txt"):
        raise Refused("commands.txt has no 'exit N: <command>' line")
    if not ev.parse_facts(directory / "host.txt"):
        raise Refused("host.txt has no key=value facts")
    return sum(len(v) for v in logs.values())


def config_target(config, dest):
    """The run configuration and its path, checked before anything is written: its
    artifacts root must be the directory that holds `dest` (paths are relative to it)."""
    cfg_path = Path(config)
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    root = Path(cfg.get("artifacts_root", ""))
    if not root.is_absolute():
        root = ROOT / root
    if root.resolve() != dest.parent.resolve():
        raise Refused("the configuration's artifacts_root is not the directory the bundle is imported into")
    return cfg_path, cfg


def import_bundle(text, label, artifacts_root, config=None, commit=None):
    """(directory, digest, tests) after writing the files; raises Refused before writing."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", label or ""):
        raise Refused("the label must be [A-Za-z0-9._-] and not start with punctuation")
    doc = decode(text)
    files = validate(doc, commit)
    dest = Path(artifacts_root) / label / "windows"
    if dest.exists() and (not dest.is_dir() or any(dest.iterdir())):
        raise Refused(f"{dest} exists and is not empty: an import never overwrites")
    target = config_target(config, dest) if config else None
    # Checked in a staging directory next to the destination, then renamed into place.
    stage = dest.with_name(".windows-import")
    if stage.exists():
        raise Refused(f"{stage} exists (an interrupted import): remove it first")
    stage.mkdir(parents=True)
    try:
        for name, body in files.items():
            (stage / name).write_text(body, encoding="utf-8", newline="\n")
        n = check_readable(load_generator(), stage)
        if dest.exists():
            dest.rmdir()
        stage.rename(dest)
    except BaseException:
        for p in stage.glob("*"):
            p.unlink()
        stage.rmdir()
        raise
    h = hashlib.sha256()
    for name in FILES:
        h.update(name.encode() + b"\0" + (dest / name).read_bytes() + b"\0")
    digest = h.hexdigest()
    if target:
        cfg_path, cfg = target
        win = dict(cfg.get("platforms", {}).get("windows", {}))
        win.pop("unavailable", None)
        win.update({
            "label": doc.get("label") or "windows (local mode)",
            "logs": ["windows/tests.txt"],
            "commands_logs": ["windows/commands.txt"],
            "facts": ["windows/host.txt"],
            "artifact_digest": digest,
        })
        cfg.setdefault("platforms", {})["windows"] = win
        cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return dest, digest, n


def read_report(path):
    """The report text, reading at most MAX_REPORT + 1 bytes from the open file (ADR-0007 §12.38
    item 4, L04): a larger report is refused before it is decoded or held whole."""
    with open(path, "rb") as f:
        data = f.read(MAX_REPORT + 1)
    if len(data) > MAX_REPORT:
        raise Refused("the report is larger than the bundle bound")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise Refused(f"the report is not UTF-8: {e}") from None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--bundle", required=True, help="report or bundle.b64 holding the bundle")
    ap.add_argument("--label", required=True, help="artifacts directory name, e.g. exit-<commit>")
    ap.add_argument("--config", help="run configuration whose windows platform is pointed at the files")
    ap.add_argument("--commit", help="the exit commit the bundle must name")
    ap.add_argument("--artifacts-root", default=str(ROOT / "tests" / "evidence" / "artifacts" / "m02"))
    a = ap.parse_args(argv)
    try:
        text = read_report(a.bundle)
    except OSError as e:
        print(f"import: cannot read the bundle: {e}", file=sys.stderr)
        return 2
    except Refused as e:
        print(f"import refused (nothing written): {e}", file=sys.stderr)
        return 1
    try:
        dest, digest, n = import_bundle(text, a.label, a.artifacts_root, a.config, a.commit)
    except Refused as e:
        print(f"import refused (nothing written): {e}", file=sys.stderr)
        return 1
    print(f"imported {len(FILES)} files ({n} test results) into {dest}; artifact digest {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
