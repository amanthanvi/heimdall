#!/usr/bin/env python3
"""Import a Windows local-mode results bundle (run-windows-local.ps1; ADR-0007 §12.32 item 17)
into tests/evidence/artifacts/m02/<label>/windows/ and feed it to the evidence generator.

Usage (from the repository root, with `python3 -I`):
  import-windows-bundle.py --bundle REPORT --label LABEL [--config RUNS.json] [--commit HEX]
                           [--artifacts-root DIR] [--platform-dir DIR] [--format FORMAT]

--format selects the bundle's format and markers: the default is the M02 local-mode bundle; the M05
WSL hook harness (tests/native/m05/run-wsl-hook-windows.ps1, ruling I-19) writes
`heimdall-m05-wsl-hook-bundle/1`, imported with `--format heimdall-m05-wsl-hook-bundle/1
--platform-dir wsl-distro` (the same six result files).

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
# ⟨M05 wave 4, ruling I-19⟩ The WSL hook harness's bundle: the same six files, its own format and markers.
FORMAT_M05_WSL_HOOK = "heimdall-m05-wsl-hook-bundle/1"
MARKERS = {
    FORMAT: (BEGIN, END),
    FORMAT_M05_WSL_HOOK: ("-----BEGIN HEIMDALL M05 WSL HOOK BUNDLE-----", "-----END HEIMDALL M05 WSL HOOK BUNDLE-----"),
}
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
# A home component (W6X-R03 and its re-check): one or more characters that are not a path
# separator, whitespace, a quote or bracket, or the shell and prose punctuation that ends a
# path in text (a backtick, comma, pipe, semicolon, colon, `$`, `*`, `?`, `#`, `=`, `&`,
# `!`, parentheses and brackets). So `+name`, `é-name` and an emoji-led name are home
# names, while `` `/Users/` ``, `/home/,` and `/home/$U` (a variable) are not.
_HOME_STOP = r"\s/\\\"'<>`,|;:$*?#=&!()\[\]{}"
_HOME_NAME = rf"[^{_HOME_STOP}]+"
_HOME_END = rf"[{_HOME_STOP}]|\Z"
_SENSITIVE = (
    (re.compile(r"HEIMDALL_CANARY_"), "a canary prefix"),
    (re.compile(r"S-1-(5-21|12-1)-\d"), "an unmasked user or domain SID"),
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"), "private-key armor"),
    # ADR-0007 §12.38 item 3 (L03) and the K01 review: only an exact system profile component is
    # exempt: the name must be followed by a separator, a quote, a bracket or the end, never by
    # whitespace (which can sit inside a personal name: "Public Alice"); the longer names are
    # tried first, so "Default User.Alice" is not exempted as "Default".
    (re.compile(r"(?i)\b[A-Z]:[\\/]+Users[\\/]+(?!<|(?:Default User|All Users|Public|Default)(?=[\\/\"'<>]|$))[^\\/\s\"'<>]+"),
     "an unredacted Windows home path"),
    (re.compile(r"(?i)/mnt/[a-z]/Users/(?!<|(?:Default User|All Users|Public|Default)(?=[/\"'<>]|$))[^/\s\"'<>]+"),
     "an unredacted Windows home path"),
    # A home under /home, anywhere a name may start; a home component is `_HOME_NAME`. The
    # only exemption (W6W-R01, narrowed by W6X-R03) is a fixture's own `home` directory inside
    # a redacted root, followed by exactly one of the fixture entries the harnesses print and
    # then a separator or the end: `<scratch>/home/.gitconfig`, `<scratch>/home/.config` (Git's
    # XDG file, observed in the Windows exit run at 1e69263d) and `<scratch>/home/.ssh`. Any
    # other dot entry (`<scratch>/home/.private/name`, `<scratch>/home/.ssh+name`), a bare
    # `/home/.name` and `<scratch>/home/name` are refused: a home directory need not follow
    # user-name rules.
    # A run of separators before `home` is one separator to the kernel (`//home/name` is
    # `/home/name`; the exit-gaps review, R2), so each rule takes one or more.
    (re.compile(rf"(?<![\w/.>-])/+home/(?!<){_HOME_NAME}"), "an unredacted Unix home path"),
    (re.compile(rf"(?<=>)/+home/(?!<|\.(?:gitconfig|config|ssh)(?={_HOME_END})){_HOME_NAME}"),
     "an unredacted Unix home path"),
    # The macOS form is not applied right after a lone drive letter (C:/Users/... is the
    # Windows rule's), but it is after any other colon (PATH=...:/Users/x, file:/Users/x).
    (re.compile(rf"(?<![\w/.-])(?<!\b[A-Za-z]:)/+Users/(?!<|Shared(?=[/\"'<>]|$)){_HOME_NAME}"),
     "an unredacted macOS home path"),
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


def decode(text, fmt=FORMAT):
    """The bundle document from a report that contains it between the markers of `fmt`."""
    begin_marker, end_marker = MARKERS[fmt]
    if len(text) > MAX_REPORT:
        raise Refused("the report is larger than the bundle bound")
    start = text.find(begin_marker)
    end = text.find(end_marker, start + 1 if start >= 0 else 0)
    if start < 0 or end < 0:
        raise Refused("no bundle between the BEGIN and END markers")
    if text.find(begin_marker, start + 1) >= 0 and text.find(begin_marker, start + 1) < end:
        raise Refused("a second BEGIN marker before the END marker")
    lines = [l.strip() for l in text[start + len(begin_marker):end].splitlines() if l.strip()]
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


def validate(doc, commit=None, fmt=FORMAT):
    """The checked files {name: text} of a decoded bundle."""
    if not isinstance(doc, dict) or doc.get("format") != fmt:
        raise Refused(f"not a {fmt} bundle")
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


def import_bundle(text, label, artifacts_root, config=None, commit=None, platform="windows", fmt=FORMAT):
    """(directory, digest, tests) after writing the files; raises Refused before writing.

    ⟨M03 wave 6⟩ `platform` is the platform directory and runs.json platform name (default
    `windows`; tests/native/m03/lock-windows.ps1's bundle imports as `windows-lock`).
    ⟨M05 wave 4⟩ `fmt` is the bundle format (a key of MARKERS); the M05 WSL hook bundle imports
    as platform `wsl-distro`."""
    if fmt not in MARKERS:
        raise Refused(f"unknown bundle format {fmt!r}")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", label or ""):
        raise Refused("the label must be [A-Za-z0-9._-] and not start with punctuation")
    if not re.fullmatch(r"windows(-[a-z0-9]+)?|wsl-distro", platform or ""):
        raise Refused("the platform directory must be windows, windows-<word> or wsl-distro")
    doc = decode(text, fmt)
    files = validate(doc, commit, fmt)
    dest = Path(artifacts_root) / label / platform
    if dest.exists() and (not dest.is_dir() or any(dest.iterdir())):
        raise Refused(f"{dest} exists and is not empty: an import never overwrites")
    target = config_target(config, dest) if config else None
    # Checked in a staging directory next to the destination, then renamed into place.
    stage = dest.with_name(f".{platform}-import")
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
        win = dict(cfg.get("platforms", {}).get(platform, {}))
        win.pop("unavailable", None)
        win.update({
            "label": doc.get("label") or "windows (local mode)",
            "logs": [f"{platform}/tests.txt"],
            "commands_logs": [f"{platform}/commands.txt"],
            "facts": [f"{platform}/host.txt"],
            "artifact_digest": digest,
        })
        cfg.setdefault("platforms", {})[platform] = win
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
    ap.add_argument("--platform-dir", default="windows",
                    help="the platform directory and runs.json platform (windows, windows-<word> such as windows-lock, or wsl-distro)")
    ap.add_argument("--format", default=FORMAT, choices=sorted(MARKERS),
                    help="the bundle format (default: the M02 local-mode bundle)")
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
        dest, digest, n = import_bundle(text, a.label, a.artifacts_root, a.config, a.commit, a.platform_dir, a.format)
    except Refused as e:
        print(f"import refused (nothing written): {e}", file=sys.stderr)
        return 1
    print(f"imported {len(FILES)} files ({n} test results) into {dest}; artifact digest {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
