#!/usr/bin/env python3
"""X1d: install the harness's two pinned wheels into a venv that has no pip, by hash-checked extraction.

usage: <venv>/bin/python -I wheel-install.py <requirements.txt> <wheel-dir>

Used only where `python3 -m venv` cannot install pip (Debian without python3-venv: ensurepip missing) and no
package may be installed system-wide. For every `name==version --hash=sha256:<hex>` line of requirements.txt it
needs exactly one <wheel-dir>/<name>-<version>-*.whl whose sha256 equals the pin (the same check as pip's
--require-hashes), then unpacks it into this interpreter's purelib (the venv's site-packages). Only pure-Python
wheels are accepted (Root-Is-Purelib: true, no .data directory, no absolute or '..' member). INSTALLER is written as
"x1d-wheel-install". Exit 0 when both are installed and importable, 1 otherwise.
"""
import hashlib
import importlib
import importlib.metadata
import re
import sys
import sysconfig
import zipfile
from pathlib import Path, PurePosixPath


def pins(req):
    text = Path(req).read_text(encoding="utf-8").replace("\\\n", " ")
    out = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)\s+--hash=sha256:([0-9a-f]{64})", line)
        if not m:
            sys.exit(f"unsupported requirements line: {line!r}")
        out[m.group(1).lower().replace("-", "_")] = (m.group(2), m.group(3))
    return out


def main():
    req, wdir = sys.argv[1], Path(sys.argv[2])
    if sys.prefix == sys.base_prefix:
        sys.exit("refusing: not running inside a venv")
    site = Path(sysconfig.get_paths()["purelib"]).resolve()
    print(f"target: <venv>/{site.relative_to(Path(sys.prefix).resolve())}")
    ok = True
    for name, (ver, want) in sorted(pins(req).items()):
        cands = sorted(wdir.glob(f"{name}-{ver}-*.whl"))
        if len(cands) != 1:
            print(f"{name}=={ver}: expected exactly one wheel, found {len(cands)}")
            ok = False
            continue
        whl = cands[0]
        got = hashlib.sha256(whl.read_bytes()).hexdigest()
        print(f"{whl.name}: sha256 {got} {'== pin' if got == want else '!= pin ' + want}")
        if got != want:
            ok = False
            continue
        with zipfile.ZipFile(whl) as z:
            names = z.namelist()
            distinfo = {n.split("/", 1)[0] for n in names if n.split("/", 1)[0].endswith(".dist-info")}
            if len(distinfo) != 1:
                sys.exit(f"{whl.name}: {len(distinfo)} .dist-info directories")
            di = distinfo.pop()
            meta = z.read(f"{di}/WHEEL").decode()
            if "Root-Is-Purelib: true" not in meta:
                sys.exit(f"{whl.name}: not a purelib wheel")
            for n in names:
                p = PurePosixPath(n)
                if p.is_absolute() or ".." in p.parts or p.parts[0].endswith(".data"):
                    sys.exit(f"{whl.name}: refusing member {n!r}")
                dest = (site / p).resolve()
                if site not in dest.parents and dest != site:
                    sys.exit(f"{whl.name}: member {n!r} escapes the target")
            z.extractall(site)
            (site / di / "INSTALLER").write_text("x1d-wheel-install\n", encoding="utf-8")
            print(f"  extracted {len(names)} members, dist-info {di}")
    importlib.invalidate_caches()
    for mod in ("pyte", "wcwidth"):
        try:
            importlib.import_module(mod)
            print(f"import {mod}: ok, version {importlib.metadata.version(mod)}")
        except Exception as exc:  # noqa: BLE001 - report and fail
            print(f"import {mod}: {type(exc).__name__}")
            ok = False
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
