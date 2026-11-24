# What Heimdall does not do

> **Draft (M08 U7a, 2026-11-22), provisional.** Written on today's command names; M06 and M07 will rename some, and `tools/validation/docs_commands_check.py` fails this file until it follows. Commands in blocks marked `planned` do not exist yet (ADR-0014 §7 names their contract delta). Nothing here is a release claim.

Short, and meant to be read once.

- **Programs running as you can use what you can use.** A project's access is separate from
  another project's, but Heimdall does not sandbox programs running under your own account
  from each other. Where real isolation exists, the matrix says which mechanism provides it.
- **Some prompts are not Heimdall's to remove.** A password manager, a hardware key or a
  provider that insists on a touch or an unlock will still ask.
- **Stopping access does not close what is already open.** A shell or a forward that is
  connected keeps working until it ends. New connections stop at once.
- **A certificate already issued stays valid until it expires,** including at a host that
  is offline when you revoke. Heimdall shows the latest such expiry.
- **A sleeping or powered-off machine does no work.** Locking the screen does not stop
  approved background work; sleep, logout and reboot each behave as the status view says.
- **Uninstalling does not remove lines on remote hosts.** Remove enrollments first.
- **Only the combinations in the compatibility matrix were tested.** Others may work.
- **The Iroh transport is not in this release.** It is a preview you can build from source
  (`cargo build --features iroh`), with no support claim. Direct and jump routes work without it.
- **What was not run before this release:** see the release notes. Rows that needed
  machines or accounts that were not available are listed there as not run, not as passed.
