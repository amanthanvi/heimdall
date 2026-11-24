#!/usr/bin/env python3
"""M06 exit (RESEARCH §0 items 1, 5): bring the Windows controller journey's output back from the
PC into <artifacts_root>/windows-controller/ and point the exit configuration at it.

The journey (tests/native/m06/run-windows-controller.ps1) runs on the PC through its recorder,
tests/native/m06/record-windows-controller.ps1, which writes beside the journey's own tests.txt
and host.txt:
  * commands.txt: one `exit <code>: <command>` line, the code being the journey process's real
    exit status ($LASTEXITCODE), written by the process that started it;
  * build.txt: the commit of the checkout it ran from and the sha256 of the four input binaries
    and of the journey script.
The integrator copies that directory to the build host; this script then imports it.

The import refuses (exit 1, nothing written):
  * a file that is not one of tests.txt, host.txt, commands.txt, build.txt and the optional
    ssh-stderr.txt, a missing required file, a file over 16 MiB or not UTF-8;
  * any file carrying a canary prefix, an unmasked user or domain SID, private-key armor, an
    unredacted home path or a non-loopback IPv4 address (import-windows-bundle.py's checks,
    reused, not copied);
  * a tests.txt without the journey's results or without exactly one
    `### windows-controller-journey exit=N` trailer (written by the journey itself);
  * a commands.txt that is not exactly the recorder's one line, or whose exit code is 0 while
    the journey's own trailer is not (a pass the journey never reported). The other
    disagreement is kept, not refused: the recorder sees 1 after the journey wrote exit=0 when
    the journey could not remove its run directory, and the nonzero code then fails the row;
  * a build.txt without a 40-hex `commit=` (with --commit: exactly that one) or without the
    five sha256 lines;
  * a destination that exists and is not empty (an import never overwrites).
With --config the run configuration's `windows-controller` platform is pointed at the files
(logs, commands_logs, facts, artifact_digest: the sha256 over the imported files) and any
`unavailable` mark or configured `exit_codes` map is dropped: the exit code is the recorder's,
never one typed into the configuration (m06-evidence.py refuses a configured map there).

Usage (repository root):
  python3 -I tests/native/m06/import-windows-controller.py --from DIR --artifacts-dir $A
      [--commit <40hex>] [--config $A/runs.json]
Exit: 0 imported, 1 refused, 2 usage.
"""

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PLATFORM = "windows-controller"
JOURNEY = "windows-controller-journey"
REQUIRED = ("tests.txt", "host.txt", "commands.txt", "build.txt")
OPTIONAL = ("ssh-stderr.txt",)
MAX_FILE = 16 * 1024 * 1024
# The recorder's command text (record-windows-controller.ps1, $Command): no path, no name.
COMMAND = "pwsh -NoProfile -File tests/native/m06/run-windows-controller.ps1 (the Windows controller journey, through record-windows-controller.ps1)"
BUILD_NAMES = (
    "heimdall.exe",
    "e2e_windows_controller_m06.exe",
    "heimdall (linux x86_64)",
    "e2e_windows_controller_m06 (linux x86_64)",
    "run-windows-controller.ps1",
)
TRAILER = re.compile(rf"(?m)^### {JOURNEY} exit=(-?\d+)$")


class Refused(Exception):
    """Nothing is imported."""


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


BUNDLE = load("import_windows_bundle", HERE.parent / "m02" / "import-windows-bundle.py")


def trailer_code(text):
    """The journey's own exit code from its tests.txt trailer (exactly one), else Refused."""
    found = TRAILER.findall(text)
    if len(found) != 1:
        raise Refused(f"tests.txt has {len(found)} '### {JOURNEY} exit=N' lines, not exactly one")
    return int(found[0])


def recorded_code(text):
    """The recorder's exit code: commands.txt must be exactly its one line."""
    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) != 1:
        raise Refused("commands.txt is not exactly the recorder's one line")
    m = re.fullmatch(r"exit (-?\d+): (.+)", lines[0])
    if not m or m.group(2) != COMMAND:
        raise Refused("commands.txt is not the recorder's 'exit N: <command>' line")
    return int(m.group(1))


def check_codes(recorded, journey):
    """A recorded pass needs the journey's own pass; the higher code otherwise stands."""
    if recorded == 0 and journey != 0:
        raise Refused(f"commands.txt records exit 0 but the journey's own trailer says exit={journey}")


def build_facts(text, commit=None):
    """{name: sha256} and the commit from the recorder's build.txt."""
    m = re.findall(r"(?m)^commit=([0-9a-f]{40})$", text)
    if len(m) != 1:
        raise Refused("build.txt names no single 40-hex commit")
    if commit and m[0] != commit:
        raise Refused("build.txt is for another commit")
    sums = {}
    for name, digest in re.findall(r"(?m)^(.+) sha256: ([0-9a-f]{64})$", text):
        sums.setdefault(name, digest)
    missing = [n for n in BUILD_NAMES if n not in sums]
    if missing:
        raise Refused(f"build.txt has no sha256 for {', '.join(missing)}")
    return m[0], sums


def read_files(src):
    if not src.is_dir():
        raise Refused(f"{src} is not a directory")
    names = sorted(p.name for p in src.iterdir())
    extra = [n for n in names if n not in REQUIRED + OPTIONAL]
    if extra:
        raise Refused(f"unexpected files: {', '.join(extra)}")
    missing = [n for n in REQUIRED if n not in names]
    if missing:
        raise Refused(f"missing files: {', '.join(missing)} (a blocked journey writes none: mark the platform unavailable)")
    out = {}
    for n in names:
        p = src / n
        if not p.is_file() or p.is_symlink():
            raise Refused(f"{n} is not a regular file")
        if p.stat().st_size > MAX_FILE:
            raise Refused(f"{n} is larger than 16 MiB")
        try:
            text = p.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            raise Refused(f"{n} is not UTF-8") from None
        why = BUNDLE.sensitive(text)
        if why:
            raise Refused(f"{n} carries {why}")
        out[n] = text
    return out


def digest_of(files):
    h = hashlib.sha256()
    for name in sorted(files):
        h.update(name.encode() + b"\0" + files[name].encode("utf-8") + b"\0")
    return h.hexdigest()


def import_dir(src, artifacts_dir, commit=None, config=None):
    """(destination, digest, journey exit, recorded exit); raises Refused before writing."""
    files = read_files(Path(src))
    ev = BUNDLE.load_generator()
    journey = trailer_code(files["tests.txt"])
    recorded = recorded_code(files["commands.txt"])
    check_codes(recorded, journey)
    build_facts(files["build.txt"], commit)
    dest = Path(artifacts_dir) / PLATFORM
    if dest.exists() and (not dest.is_dir() or any(dest.iterdir())):
        raise Refused(f"{dest} exists and is not empty: an import never overwrites")
    target = BUNDLE.config_target(config, dest) if config else None
    stage = dest.with_name(f".{PLATFORM}-import")
    if stage.exists():
        raise Refused(f"{stage} exists (an interrupted import): remove it first")
    stage.mkdir(parents=True)
    try:
        for name, body in files.items():
            (stage / name).write_text(body, encoding="utf-8", newline="")
        logs = ev.parse_log(stage / "tests.txt")
        if not logs.get(JOURNEY):
            raise Refused("tests.txt has no journey results the generator reads")
        if not ev.parse_facts(stage / "host.txt"):
            raise Refused("host.txt has no key=value facts")
        if dest.exists():
            dest.rmdir()
        stage.rename(dest)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    digest = digest_of(files)
    if target:
        cfg_path, cfg = target
        p = dict(cfg.get("platforms", {}).get(PLATFORM, {}))
        p.pop("unavailable", None)
        p.pop("exit_codes", None)
        p.update({
            "logs": [f"{PLATFORM}/tests.txt"],
            "commands_logs": [f"{PLATFORM}/commands.txt"],
            "facts": [f"{PLATFORM}/host.txt"],
            "artifact_digest": digest,
        })
        cfg.setdefault("platforms", {})[PLATFORM] = p
        cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return dest, digest, journey, recorded


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--from", dest="src", required=True, help="the directory copied back from the PC")
    ap.add_argument("--artifacts-dir", required=True, help="the exit directory (the configuration's artifacts_root)")
    ap.add_argument("--commit", help="the exit commit build.txt must name")
    ap.add_argument("--config", help="the exit run configuration to point at the files")
    a = ap.parse_args(argv)
    if a.commit and not re.fullmatch(r"[0-9a-f]{40}", a.commit):
        print("--commit must be 40 lowercase hex digits", file=sys.stderr)
        return 2
    try:
        dest, digest, journey, recorded = import_dir(a.src, a.artifacts_dir, a.commit, a.config)
    except Refused as e:
        print(f"import refused (nothing written): {e}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as e:
        print(f"import failed (nothing written): {e}", file=sys.stderr)
        return 1
    print(f"imported {sum(1 for _ in dest.iterdir())} files into {dest}; journey exit={journey}, recorded exit={recorded}; artifact digest {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
