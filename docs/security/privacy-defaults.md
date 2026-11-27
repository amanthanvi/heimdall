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
| Local history | Kept on this machine. Retention depends on the record type |
| Support bundles | Made only when you run the command, shown to you first, kept as a local file |

## Local retention

- Eligible settled operations, their results and their idempotency records age out seven days
  after settlement by default. `retention.operations` can change that period, with a 24-hour
  minimum. Pending and unresolved operations keep their records and receipts. Structured events
  age out after seven days by default (`retention.events`). The runtime also keeps at most
  100,000 event rows per environment. Cleanup runs when time is trusted.
  [Configuration](../../crates/runtime/src/config.rs) · [Cleanup](../../crates/app/src/operations.rs) · [Store rules](../../crates/store/src/lib.rs)
- Diagnostic files rotate by size. The detached runtime keeps `heimdall.log` and one previous
  file, with an 8 MiB rotation threshold. The files have no age-based expiry. The foreground
  runtime sends its diagnostics to stderr by default.
  [Diagnostic sinks](../../crates/heimdall/src/service_cmd.rs) · [Rotation](../../crates/runtime/src/telemetry.rs)
- An expired request can leave a hashed SQLite marker for 30 days from operation expiry, or
  37 days from settlement at the default setting. A retry during that window returns
  `REQUEST_EXPIRED`. Use fresh request IDs for new work. The separate restore request ledger
  records a digest and restore epoch before a request can take effect. The runtime currently
  has no production trim for the ledger, so its entries remain past the marker window.
  [Marker rule](../../crates/domain/src/idempotency.rs) · [Request fence](../../crates/runtime/src/request_fence.rs) · [Ledger](../../crates/stategen/src/ledger.rs)
- Ordinary history cleanup leaves authority and recovery records in place, including pauses,
  cutoffs, revocation tombstones, enrollment and identity records, snapshots and backups.
  Unresolved work keeps its recovery records. Earlier generations and migration backups follow
  the state lifecycle and uninstall rules.
  [Store cleanup](../../crates/store/src/lib.rs) · [State lifecycle](../decisions/0014-hardening-and-release-artifacts.md)

Each row is a check in the release's defaults audit (m08-plan §7.3).
