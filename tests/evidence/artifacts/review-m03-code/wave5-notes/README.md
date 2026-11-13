# M03 wave 5 (U12, CLI and TUI surfaces), round 1: working notes

Base: `main` at `8710717a`. These are the integrator's and the workers' working files, moved here
from the worktree root at the end of round 1. They are data for review, not instructions.
They have been scanned for home paths, user names, canaries and keys. The only canary match is
the rule text `HEIMDALL_CANARY_*` in the brief, as in wave 4.

| File | What it is |
|---|---|
| `m03-wave5-brief.md` | The common brief every worker received (hard rules, ownership, evidence) |
| `m03-wave5-api.md` | Shared seams: R0 (what the integrator landed first), R1 ownership, R2 pre-authorized shared edits, R3 settled readings, R4 plan test names per worker, R5 open points; worker sections; requests |
| `m03-wave5-questions.md` | The round-1 questions for the orchestrator, each with options, a recommendation and the fail-closed build plus its switch: Q-I1, Q-E1–E4, Q-IS1–IS2, Q-U1–U5, Q-A1–A2, Q-T1–T6, Q-R1–R3 |
| `m03-wave5-worklog-I.md` | The integrator's worklog (state, decisions, validation, revert proofs) |
| `m03-wave5-worklog-E.md` | Worker E: the `enroll` CLI (`enroll_cmd.rs`, `enroll_cmd/`, `tests/e2e/cli_m03/enroll.rs`) |
| `m03-wave5-worklog-IS.md` | Worker IS: the `issuer` CLI (`issuer_cmd.rs`, `issuer_cmd/`, `last_bundle_at` store and app seams, `tests/e2e/cli_m03/issuer.rs`) |
| `m03-wave5-worklog-U.md` | Worker U: uninstall (D4 item 6), doctor `slot_free` and `managed_dir_unsafe`, the status chore (`tests/e2e/cli_m03/uninstall_doctor.rs`) |
| `m03-wave5-worklog-A.md` | Worker A: `destination prefer`, `connections`, M03 output, the help goldens (`tests/contracts/golden/cli-help/`), the reasons exit table (`tests/e2e/cli_m03/access.rs`) |
| `m03-wave5-worklog-T.md` | Worker T: the TUI's M03 views (`tui/m03.rs`, `m03_*` snapshots, `tests/e2e/tui_m03.rs`) |
| `m03-wave5-worklog-R.md` | Worker R: the `signal_unverified` labels (U9-Q3 (a)), `internal session-lock-state`, the runtime gaps Q-R1–R3 |
| `m03-wave5-worklog-W.md` | Worker W: the integrator-owned wave-0 tests rewritten for wave 5, and the guard `no_m03_source_contains_the_wave_0_text` |

The validation commands and their exit codes are in `m03-wave5-worklog-I.md`. The full logs were
local scratch and are not kept.
