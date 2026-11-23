# Privacy defaults

> **Draft (M08 U7a, 2026-11-22), provisional.** Written on today's command names; M06 and M07 will rename some, and `tools/validation/docs_commands_check.py` fails this file until it follows. Commands in blocks marked `planned` do not exist yet (ADR-0014 §7 names their contract delta). Nothing here is a release claim.

After a default install, setup and first use:

| | Default |
|---|---|
| Usage data, telemetry | None. There is nothing to turn off |
| Network connections made by Heimdall itself | None. Your `ssh` connects to your hosts as before |
| Listening network ports | None. Local control uses a per-user socket or named pipe |
| Recording of commands, output or keystrokes | None |
| Reachability through a relay or peer-to-peer transport | Off until you enable it |
| Plug-ins, helpers or skills installed or loaded automatically | None |
| Update checks and self-update | None |
| Local history | Seven days, in bounded files, on this machine only |
| Support bundles | Made only when you run the command, shown to you first, kept as a local file |

Deleting local history never deletes a stop, a pause or a revocation.

Each row is a check in the release's defaults audit (m08-plan §7.3).
