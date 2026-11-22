# Install

> **Draft (M08 U7a, 2026-11-22), provisional.** Written on today's command names; M06 and M07 will rename some, and `tools/validation/docs_commands_check.py` fails this file until it follows. Commands in blocks marked `planned` do not exist yet (ADR-0014 §7 names their contract delta). Nothing here is a release claim.

Heimdall ships as one archive per platform. Nothing is installed system-wide, nothing needs
administrator rights, and your `~/.ssh` is not touched until you run `heimdall setup` and
confirm what it shows.

## 1. Check the archive before you unpack it

The checksum index `SHA256SUMS` lives in the Heimdall repository, under
`tests/evidence/artifacts/m08/release/<version>/`. Take it from there, not from wherever
the archive came from.

```
shasum -a 256 -c SHA256SUMS --ignore-missing      # macOS, Linux
```

On Windows, compare `Get-FileHash -Algorithm SHA256 <archive>` with the line for that file.
**If the digest differs, stop.** The install script inside the archive cannot make this
check for you: a replaced archive would carry a replaced script.

What the release does and does not carry by way of signatures is stated in the release
notes. Unsigned means unsigned.

## 2. Unpack and install

```planned
./install.sh              # macOS, Linux (inside the unpacked directory)
.\install.ps1             # Windows
```

The script checks the unpacked files against `MANIFEST.sha256`, copies the executable to a
fixed per-user location, and prints the line you may add to your `PATH`. It does not edit
your shell profile. On Windows it also places the Linux helper that WSL support uses.

## 3. Set up

```
heimdall setup
heimdall status
heimdall doctor
```

`heimdall setup` shows every change it would make to your SSH and Git configuration and asks
before making it. Ordinary `ssh` keeps working with or without Heimdall.

## What installing does not do

- It starts nothing at login. `heimdall service autostart enable` does, after showing you
  the exact entry and asking.
- It contacts no network service and sends no usage data.
- It enrolls nothing on any remote host.
