# Update and roll back

> **Draft (M08 U7a, 2026-11-22), provisional.** Written on today's command names; M06 and M07 will rename some, and `tools/validation/docs_commands_check.py` fails this file until it follows. Commands in blocks marked `planned` do not exist yet (ADR-0014 §7 names their contract delta). Nothing here is a release claim.

Heimdall never updates itself. An update is you running a newer archive's install script.

## Before you update

```planned
heimdall service stop --preview
```

This lists what stopping the runtime interrupts and changes nothing. In short:

- **New connections and signatures** through Heimdall wait until the runtime starts again.
- **Sessions that are already open keep running.** Heimdall does not close a shell you are in.
- **Working keys held only in memory are gone.** Access you already approved is re-issued
  within its unchanged terms after the restart. Nothing that had ended comes back.
- **WSL and container endpoints** are unavailable until the restart.
- **On macOS, with a build that has no Developer ID signature,** the issuer may lose access
  to its CA key after the update. Have your offline backup and its passphrase at hand; see
  `docs/release-notes/m03-macos-ca-key-access.md`.

## Update

1. Verify the new archive against `SHA256SUMS` from the repository (see `install.md`).
2. Stop the runtime: `heimdall service stop`.
3. Run the new archive's install script. It keeps your current executable as
   `heimdall.previous`. If it is interrupted, run it again: it finishes the update. Until then
   the install path still holds a complete executable, the old one or the new one (macOS and
   Linux). On Windows a running program cannot be replaced in one step, so for an instant
   the install path has no `heimdall.exe`; if the install stops exactly there, your previous
   executable and its WSL helper are complete under their `.previous` names, and running the
   script again finishes the update. On every platform the executable and its helper are
   replaced together, never one without the other. If it
   cannot keep your current executable (for example, the disk is full), it stops before
   replacing anything and says so.
4. `heimdall status`, then `heimdall doctor`.

An update keeps your environment's identity, your profiles, your stops and pauses, your
revocations and your enrollments. If the state needs a new format, Heimdall writes a backup
first.

## Roll back

- **Same state format:** put `heimdall.previous` back (rerun the older archive's install
  script). It serves the same state.
- **The state format changed:** the older executable refuses the newer state and changes
  nothing. Going back then means a restore (see `recovery.md`), which keeps your identity
  and settings and ends all access so that you approve it again.
- **One boundary is one-way:** a pre-release build that predates store generations cannot
  be rolled back to once the newer build has started adopting its state. Every released
  build is on the newer side of that boundary.
