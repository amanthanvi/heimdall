#!/usr/bin/env python3
"""Check a file-only install of the release payload using disposable executables."""
import argparse
import os
from pathlib import Path
import runpy
import shutil
import stat
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
DESKTOP_STARTUP_CACHE = "local/Microsoft/Windows/PowerShell/StartupProfileData-NonInteractive"


def snapshot(root, optional_file=None):
    entries = {}
    pending = [root]
    while pending:
        path = pending.pop()
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        name = path.relative_to(root).as_posix()
        is_reparse = getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        if stat.S_ISLNK(info.st_mode) or is_reparse:
            entries[name] = "link or reparse point"
        elif stat.S_ISDIR(info.st_mode):
            entries[name] = None
            pending.extend(path.iterdir())
        elif stat.S_ISREG(info.st_mode):
            if name != optional_file:
                entries[name] = path.read_bytes()
        else:
            entries[name] = "special file"
    return entries


def check_tree(failure, tree, root, expected, optional_file=None):
    try:
        found = snapshot(root, optional_file)
    except OSError as exc:
        path = Path(exc.filename).relative_to(root).as_posix() if exc.filename else "."
        print(f"{failure} {tree} tree: cannot read {ascii(path)} ({type(exc).__name__})")
        return False
    differences = {
        "unexpected": found.keys() - expected.keys(),
        "missing": expected.keys() - found.keys(),
        "changed": {name for name in found.keys() & expected.keys() if found[name] != expected[name]},
    }
    for kind, paths in differences.items():
        for path in sorted(paths):
            print(f"{failure} {tree} tree: {kind} path {ascii(path)}")
    return not any(differences.values())


def check(shell):
    shell_name = Path(shell).stem.lower()
    windows = shell_name in ("powershell", "pwsh")
    desktop = os.name == "nt" and shell_name == "powershell"  # Windows PowerShell 5.1
    with tempfile.TemporaryDirectory(prefix="hm-payload-install-") as tmp:
        root = Path(tmp)
        stage, home, prefix = root / "stage", root / "home", root / "install"
        home.mkdir()
        payload = runpy.run_path(str(HERE / "release_payload.py"))
        payload["stage"](stage)
        for name in (payload["SKILL"], "examples/" + payload["SKILL"]):
            # If mistakenly sourced by the installer, create a detectable side effect.
            marker = ('New-Item -Path "$env:USERPROFILE/skill-loaded" -ItemType File'
                      if windows else 'touch "$HOME/skill-loaded"')
            (stage / name).write_text(marker + "\n", encoding="utf-8")
        if windows:
            files = {"heimdall.exe": b"fixture PE", "linux-x86_64/heimdall": b"fixture ELF"}
            installer = "install.ps1"
            args = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(stage / installer),
                    "-Prefix", str(prefix), "-AssumeStopped"]
        else:
            files = {"heimdall": b'#!/bin/sh\ntouch "$HOME/unexpected-executable-run"\nexit 1\n'}
            installer = "install.sh"
            args = [str(stage / installer), "--prefix", str(prefix), "--assume-stopped"]
        for name, content in files.items():
            p = stage / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content)
            p.chmod(0o755)
        shutil.copyfile(HERE / installer, stage / installer)
        runpy.run_path(str(HERE / "provenance.py"))["write_manifest"](str(stage))
        env = dict(os.environ, HOME=str(home), USERPROFILE=str(home), APPDATA=str(home / "appdata"),
                   LOCALAPPDATA=str(home / "local"), XDG_CONFIG_HOME=str(home / "config"),
                   XDG_DATA_HOME=str(home / "data"), XDG_CACHE_HOME=str(root / "shell-cache"),
                   POWERSHELL_TELEMETRY_OPTOUT="1", POWERSHELL_UPDATECHECK="Off",
                   HEIMDALL_HOME=str(home / "heimdall"),
                   HEIMDALL_TEST_SSH_HOME=str(home / "ssh"), HEIMDALL_TEST_SECRET_STORE="scratch",
                   HEIMDALL_TEST_MGMT_STORE="fixture-file:" + str(home / "mgmt"),
                   HEIMDALL_TEST_IROH_KEY_STORE=str(home / "iroh"))
        startup_cache = None
        if desktop:
            # Windows PowerShell creates this startup cache even with -NoProfile.
            # Make its parents part of the fixture so every other path is still checked.
            startup_cache = DESKTOP_STARTUP_CACHE
            (home / startup_cache).parent.mkdir(parents=True)
            # 5.1 also has a module analysis cache. Disable it through its documented setting.
            env["PSModuleAnalysisCachePath"] = os.devnull
        expected_stage = snapshot(stage)
        expected_home = snapshot(home)
        expected_prefix = {".": None, **files}
        if windows:
            expected_prefix["linux-x86_64"] = None
        for label in ("fresh install", "reinstall"):
            failure = f"payload-install-selftest: FAIL {installer} {label}"
            installer_ok = False
            try:
                result = subprocess.run([shell, *args], cwd=stage, env=env, capture_output=True, timeout=45)
                installer_ok = result.returncode == 0
                if not installer_ok:
                    print(f"{failure} installer exit: expected 0, got {result.returncode}")
            except subprocess.TimeoutExpired:
                print(f"{failure} installer exit: timed out after 45 seconds")
            except OSError as exc:
                print(f"{failure} installer launch: {type(exc).__name__}")
            trees_ok = (
                check_tree(failure, "stage", stage, expected_stage),
                check_tree(failure, "home", home, expected_home, startup_cache),
                check_tree(failure, "prefix", prefix, expected_prefix),
            )
            if not installer_ok or not all(trees_ok):
                return False
        print(f"payload-install-selftest: PASS {installer} (fresh install and reinstall)")
        return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shell", choices=("bash", "powershell", "pwsh"), required=True)
    args = parser.parse_args()
    raise SystemExit(0 if check(args.shell) else 1)
