#!/usr/bin/env python3
"""Check a file-only install of the release payload using disposable executables."""
import argparse
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent


def snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() if p.is_file() else None
            for p in root.rglob("*")}


def check(shell):
    windows = Path(shell).stem.lower() in ("powershell", "pwsh")
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
            args = ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(stage / installer),
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
        before = snapshot(stage)
        expected = dict(files)
        if windows:
            expected["linux-x86_64"] = None
        for label in ("fresh install", "reinstall"):
            result = subprocess.run([shell, *args], cwd=stage, env=env, capture_output=True, timeout=45)
            if result.returncode or snapshot(stage) != before or snapshot(home) or snapshot(prefix) != expected:
                print(f"payload-install-selftest: FAIL {installer} {label} (installer exit {result.returncode})")
                return False
        print(f"payload-install-selftest: PASS {installer} (fresh install and reinstall)")
        return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shell", choices=("bash", "powershell", "pwsh"), required=True)
    args = parser.parse_args()
    raise SystemExit(0 if check(args.shell) else 1)
