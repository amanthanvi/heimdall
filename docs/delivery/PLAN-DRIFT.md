# PLAN Drift Notes (Reconciled)

## Findings

1. **TUI wiring over-claimed**
   - `PLAN.md` marked Batch 5 TUI command entrypoint done.
   - Code had `internal/tui/*` but no CLI command registration in `internal/cli/root.go`.
   - Fixed by adding `heimdall tui` with `ui` alias and wiring.

2. **JSON import identity handling over-claimed**
   - CLI JSON import loop counted identity metadata as imported.
   - It did not create/import usable identities via CLI path.
   - Fixed by reporting identity metadata as skipped explicitly.

3. **Release-line cleanup target drift**
   - Plan previously retained `v0.1.23` as rollout line.
   - Current policy is to leave only `v0.2.0` public.
   - `PLAN.md` updated with explicit `todo` for release/tag prune.

4. **Connection audit semantics drift**
   - v0.2.0 scope expected connect lifecycle audit visibility.
   - Implementation initially emitted connect lifecycle events only for managed-key connects.
   - Fixed so non-dry-run identity-file connects also record `connect.start`/`connect.end` via session start/end RPCs.

5. **Audit-default ergonomics drift**
   - Connection auditing was correct but defaulted off for generated/default configs.
   - Updated defaults to `connection_logging=true` and preserved an explicit status hint if manually disabled.

## Current outstanding plan items

- None for this reconciliation batch.
