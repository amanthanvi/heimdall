# Recovery

> **Draft (M08 U7a, 2026-11-22), provisional.** Written on today's command names; M06 and M07 will rename some, and `tools/validation/docs_commands_check.py` fails this file until it follows. Commands in blocks marked `planned` do not exist yet (ADR-0014 §7 names their contract delta). Nothing here is a release claim.

## Heimdall says its state is damaged

Heimdall stops granting access and tells you so. It never starts over silently, because
starting over would create a new identity and strand what you enrolled.

```
heimdall doctor
heimdall status
```

```planned
heimdall state status
heimdall state restore --backup <file>
heimdall state reset
```

- **Restore** rebuilds the state from one of this installation's own backups. It keeps your
  identity, destinations, profiles and enrollments. **It restores no access:** every grant
  is ended, every standing permission is paused, every paired device must be approved
  again, and a request you made before the restore is refused if retried, never run twice.
  A backup from another installation is refused.
- **Reset** starts a new installation with a new identity. It first lists what that leaves
  behind on remote hosts. If it cannot list it, it says so, and you must confirm that
  sentence. Reset never runs unattended.
- Either way, the old state is kept beside the new one until you remove it.

Your ordinary `ssh` configuration is not affected by either.

## The issuer cannot read its CA key

```
heimdall issuer status
heimdall issuer restore --backup <file>
```

Use the offline backup made when the issuer was created. The restored key is the same CA,
so remote hosts that trust it need no change.

## A device is lost

On another device that manages the same remote hosts, remove the lost device's enrollments
(see `unenrollment.md`). A replacement device gets a new identity: copying a state
directory to it does not make it the lost one.

## Asking for help

```planned
heimdall support bundle --preview
heimdall support bundle --out <file>
```

A bundle is made only when you ask, is shown to you in full first, and is a local file.
It holds codes, numbers and placeholders, never free text, keys or session content.
