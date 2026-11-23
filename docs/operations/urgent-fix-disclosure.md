# Urgent fixes

> **Draft (M08 U7a, 2026-11-22), provisional.** Written on today's command names; M06 and M07 will rename some, and `tools/validation/docs_commands_check.py` fails this file until it follows. Commands in blocks marked `planned` do not exist yet (ADR-0014 §7 names their contract delta). Nothing here is a release claim.

**What exists.** A security or data-loss fix is announced in two places in the Heimdall
repository: the release notes of the fixed version, and `SECURITY.md`. The notes say what
is affected, since which version, and what to do.

**What does not exist.** No mailing list, no in-product notice, no automatic update and no
monitoring service. Heimdall does not contact the network to check for versions. If you
depend on Heimdall, watch the repository's releases.

**Taking an urgent fix.** It is an ordinary update (`update-and-rollback.md`). A restart
that cannot wait interrupts the same things as any stop, and the stop preview lists them.

**Reporting a problem.** See `SECURITY.md` for the private reporting route. Please do not
open a public issue for a vulnerability.
