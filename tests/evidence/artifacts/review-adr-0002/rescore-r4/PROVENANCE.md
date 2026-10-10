# Scorer and reviewer provenance

| Output | Model and settings | Launched by |
|---|---|---|
| `codex/` | Codex provider, model `gpt-6.1-sol`, reasoning effort `high` | T3 Code `delegate_task`, client request `heimdall-m00-g02-rescore-codex-r1` (2026-10-10) |
| `fable/` | Claude Fable 5.1 (`claude/claude-fable-5-1`), effort `high` | workflow `heimdall-m00-g02-adr0002-blind-rescore`, run `wf_84d83401-88d` |
| `opus/` | Claude Opus 5.5, effort `high` | same workflow and run |
| `orchestrator-prereg.md` | the orchestrator (Claude Opus 5.5), session heimdall-83 | written before the scorers ran: last write 04:58:15, first scorer file 05:04:05 (local time, 2026-10-10) |
| `../review-3/fidelity/` | Codex `gpt-6.1-sol`, effort `high` | `delegate_task` `heimdall-m00-adr0002-review3-fidelity-r1`; recheck `-r2` |
| `../review-3/logic/` | Claude Fable 5.1 | Agent tool, background; recheck as a second agent |

All scorers received `SCORER-BRIEF.md` with only the scorer name and output directory substituted.
