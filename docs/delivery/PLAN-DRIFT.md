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

## Current outstanding plan items

- Prune pre-v0.2.0 releases and tags.
- Run full validation gate and publish final report evidence.
