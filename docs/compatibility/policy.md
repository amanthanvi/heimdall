# Compatibility and deprecation policy

> **Draft (M08 U7a, 2026-11-22), provisional.** Written on today's command names; M06 and M07 will rename some, and `tools/validation/docs_commands_check.py` fails this file until it follows. Commands in blocks marked `planned` do not exist yet (ADR-0014 §7 names their contract delta). Nothing here is a release claim.

**Approval:** the contract owner approves this text with public-contract revision 7
(ADR-0013). Until then it is a proposal.

## What a version number promises

Heimdall uses `MAJOR.MINOR.PATCH`.

| Surface | Within one major version |
|---|---|
| CLI commands, flags, exit codes | Not removed or changed in meaning. New ones may be added |
| JSON output and schemas (`schema_version`) | Fields are added, never removed or retyped. Clients must ignore fields, event types and reasons they do not know. An unknown result code is an error |
| The local control protocol | Negotiated by capability. A client that requires a capability the runtime lacks is refused explicitly |
| The state on disk | A newer build reads and migrates an older state, after a backup. An older build refuses a newer state and changes nothing |
| Human-readable text | May change at any time. Do not parse it |

## Deprecation

Something that will be removed is first marked deprecated in the release notes and in the
installed schema. It then stays for **at least two minor releases and 90 days,** whichever
is longer, and is removed only in a new major version.

## Platforms, clients and providers

`docs/compatibility/matrix.md`, packaged with each release, labels every combination
`verified`, `supported-with-limitations`, `experimental`, `unsupported` or `not-tested`,
with the versions observed and the evidence. A label changes only with a new record. A
newer OS, OpenSSH or provider version than the ones listed is `not-tested` until it is run.

## What is outside this policy

Hidden and internal commands, the state directory's layout, log text, and anything under
`examples/`.
