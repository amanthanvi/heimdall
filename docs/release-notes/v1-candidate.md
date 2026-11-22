# Heimdall 1.0.0 release candidate: notes (skeleton)

> **Draft (M08 U7a, 2026-11-22), provisional.** Written on today's command names; M06 and M07 will rename some, and `tools/validation/docs_commands_check.py` fails this file until it follows. Commands in blocks marked `planned` do not exist yet (ADR-0014 §7 names their contract delta). Nothing here is a release claim.

**Every section below is filled from records at the candidate build. A sentence with no
record behind it is removed (m08-plan U8, the claim audit).**

## What this is
- Version, commit, date. Stable, or a named preview: decided at M09, not here.

## Artifacts and how to verify them
- One archive per platform; `SHA256SUMS` in the repository; `docs/operations/install.md`.
- **Signatures, exactly as produced:** macOS: ad-hoc signed, not notarized. Windows:
  unsigned. Linux: none. Checksums: recorded in the repository history; no signature.
  (Each line changes only if the owner supplies the key.)

## What works, and where it was verified
- From the packaged compatibility matrix.

## Known limitations
- `docs/user/limitations.md`.
- macOS without a Developer ID signature: `docs/release-notes/m03-macos-ca-key-access.md`.
- Linux arm64: built and statically checked only; not run on a native host.

## Not run before this release
- Each row, with the machine or account it needed.

## Updating, rolling back, recovering, removing
- `docs/operations/`.

## Reporting a vulnerability
- `SECURITY.md`.
