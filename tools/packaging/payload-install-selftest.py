#!/usr/bin/env python3
"""Check a file-only install of the release payload using disposable executables."""
import argparse
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
DESKTOP_STARTUP_CACHE = "AppData/Local/Microsoft/Windows/PowerShell/StartupProfileData-NonInteractive"
CORE_STARTUP_CACHE = "AppData/Local/Microsoft/PowerShell/StartupProfileData-NonInteractive"


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


def print_installer_output(failure, result, paths):
    # Python and the shell can use different spellings of the same absolute path.
    replacements = {}
    for path, label in paths:
        replacements[str(path)] = label
        try:
            replacements[str(path.resolve())] = label
        except (OSError, RuntimeError):
            # A redirected profile can be unavailable. Keep its original spelling.
            pass
    patterns = []
    flags = re.IGNORECASE if os.name == "nt" else 0
    for path in sorted(replacements, key=len, reverse=True):
        pattern = re.escape(path)
        if os.name == "nt":
            pattern = pattern.replace(re.escape(os.sep), r"[\\/]")
        patterns.append((re.compile(pattern, flags), replacements[path]))

    encoding = sys.stdout.encoding or "utf-8"
    for stream, data in (("stdout", result.stdout), ("stderr", result.stderr)):
        if not data:
            continue
        try:
            message = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            message = data.decode("oem" if os.name == "nt" else "utf-8", errors="replace")
        message = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", message)
        for pattern, label in patterns:
            message = pattern.sub(label, message)
        if os.name == "nt":
            # An unrecognized drive or UNC path can be a short or console-code-page alias.
            message = re.sub(r"(?:[a-zA-Z]:[\\/]|\\\\)[^\r\n]*", "<path>", message)
        for line in message.splitlines():
            safe_line = line.encode(encoding, errors="backslashreplace").decode(encoding)
            print(f"{failure} installer {stream} | {safe_line}")


def check(shell, *, shadow_modules=False):
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
            args = ["-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-ExecutionPolicy", "Bypass",
                    "-File", str(stage / installer), "-Prefix", str(prefix), "-AssumeStopped"]
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
        if os.name == "nt" and windows:
            # Give Windows the usual, existing profile directories, all inside the fixture.
            local, roaming = home / "AppData" / "Local", home / "AppData" / "Roaming"
            local.mkdir(parents=True)
            roaming.mkdir()
            drive, homepath = os.path.splitdrive(str(home))
            env.update(LOCALAPPDATA=str(local), APPDATA=str(roaming), HOMEDRIVE=drive, HOMEPATH=homepath)
            # Both editions can create a startup profile even with -NoProfile, at different paths.
            # Its parents are part of the fixture, and only the exact regular file may appear.
            startup_cache = DESKTOP_STARTUP_CACHE if desktop else CORE_STARTUP_CACHE
            (home / startup_cache).parent.mkdir(parents=True)
        scenario = ""
        if windows:
            # Let command discovery cache normally using a writable file in scratch space.
            env["PSModuleAnalysisCachePath"] = str(root / "ModuleAnalysisCache")
            env.pop("PSMODULEPATH" if os.name == "nt" else "PSModulePath", None)
            module_paths = []
            if desktop:
                # Windows PowerShell honors an inherited path even when it omits its built-ins.
                module_paths.append(Path(env["SYSTEMROOT"]) / "System32/WindowsPowerShell/v1.0/Modules")
            if shadow_modules:
                modules = root / "PowerShell" / "7" / "Modules"
                utility = modules / "Microsoft.PowerShell.Utility"
                utility.mkdir(parents=True)
                (utility / "Microsoft.PowerShell.Utility.psm1").write_text(
                    "function Get-FileHash { throw 'fixture PowerShell 7 Get-FileHash was selected' }\n"
                    "Export-ModuleMember -Function Get-FileHash\n",
                    encoding="ascii",
                )
                module_paths.insert(0, modules)
            if module_paths:
                env["PSModulePath"] = os.pathsep.join(map(str, module_paths))
            scenario = " [pwsh-like PSModulePath]" if shadow_modules else " [clean PSModulePath]"
        diagnostic_paths = [(stage, "<stage>"), (home, "<home>"), (prefix, "<prefix>"), (root, "<scratch>"),
                            (HERE, "<packaging>"), (Path.home(), "<user-home>")]
        for name in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"):
            if value := os.environ.get(name):
                path = Path(value)
                if path.is_absolute():
                    diagnostic_paths.append((path, "<user-home>"))
        expected_stage = snapshot(stage)
        expected_home = snapshot(home)
        expected_prefix = {".": None, **files}
        if windows:
            expected_prefix["linux-x86_64"] = None
        for label in ("fresh install", "reinstall"):
            failure = f"payload-install-selftest: FAIL {installer}{scenario} {label}"
            installer_ok = False
            try:
                result = subprocess.run([shell, *args], cwd=stage, env=env, capture_output=True, timeout=45)
                installer_ok = result.returncode == 0
                if not installer_ok:
                    print(f"{failure} installer exit: expected 0, got {result.returncode}")
                    print_installer_output(failure, result, diagnostic_paths)
            except subprocess.TimeoutExpired as exc:
                print(f"{failure} installer exit: timed out after 45 seconds")
                print_installer_output(failure, exc, diagnostic_paths)
            except OSError as exc:
                print(f"{failure} installer launch: {type(exc).__name__}")
            trees_ok = (
                check_tree(failure, "stage", stage, expected_stage),
                check_tree(failure, "home", home, expected_home, startup_cache),
                check_tree(failure, "prefix", prefix, expected_prefix),
            )
            if not installer_ok or not all(trees_ok):
                return False
        print(f"payload-install-selftest: PASS {installer}{scenario} (fresh install and reinstall)")
        return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shell", choices=("bash", "powershell", "pwsh"), required=True)
    args = parser.parse_args()
    clean_ok = check(args.shell)
    shadow_ok = args.shell == "bash" or check(args.shell, shadow_modules=True)
    raise SystemExit(0 if clean_ok and shadow_ok else 1)
