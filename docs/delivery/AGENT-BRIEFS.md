# Agent Briefs — Shared Context Pack

Use this file when spinning subagents so every agent works from the same facts.

## Repo truth anchors

- Command surface: derive from `go run ./cmd/heimdall --help` + subcommand help.
- Planning source: `PLAN.md` + `docs/delivery/PLAN-DRIFT.md`.
- Spec source: `SPEC.md` (see “Current Truth Overrides (v0.2.0)” first) + `docs/delivery/SPEC-DRIFT.md`.
- Validation evidence: `docs/delivery/VALIDATION-LOG.md`.

## Constraints

- No invented commands.
- Small/medium diffs only.
- Commit/push frequently on `main`.
- Preserve security invariants from `AGENTS.md`.

## Acceptance baseline

1. CLI/TUI commands match docs.
2. Completion install/generation paths produce hardened zsh scripts.
3. PLAN/SPEC/docs reflect actual current behavior.
4. Release/tag policy enforced (`v0.2.0` only once prune is done).
