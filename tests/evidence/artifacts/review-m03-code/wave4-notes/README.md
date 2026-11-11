# M03 wave 4 notes (U10 + U0b phase 2, the activation change set)

Working notes of the wave-4 integrator and its four parallel workers, archived as written
(home paths redacted to `~`). They are evidence of how the change set was built, not requirements;
`spec.md`, `plan.md`, `docs/architecture/m03-plan.md` and ADR-0008 (§17 rulings) remain the sources
of truth.

| File | What it is |
|---|---|
| `m03-wave4-brief.md` | The common brief every worker received (rules, ownership, report format). |
| `m03-wave4-api.md` | The seams the integrator landed first (§0–§0c), the shared readings R1–R10, each worker's landed interfaces, and the requests between workers. |
| `m03-wave4-questions.md` | The escalations: the integrator's consolidated INT-W4 rows first, then each worker's (A-Q*, U10B-Q*, U10C-Q*, U10-D-Q*), each with the fail-closed choice taken and its switch. |
| `m03-wave4-worklog.md` | The integrator's worklog: decisions D1–D5, integration steps I1–I8 and later, commands with exit codes. |
| `m03-wave4-worklog-{A,B,C,D}.md` | Each worker's worklog, including the revert runs that show each new regression failing with its fix reverted. |

Workers: **A** enrollment stage driver; **B** issuer handling, `IssuerLifecycle`, INT-Q13 verification
gate; **C** managed effect driver, credential instances, install view, re-issue, slots, revocation data;
**D** runtime start/stop order, supervisor passes, dispatch, phase-2 capabilities, managed-alias selection
classification, `preference` on `inspect destinations`.

## Round 2 (ADR-0008 §17.21)

Round 1 was checkpointed at `d74e35cf`. Round 2 worked through §17.21 items 1–11 with workers **R2-A**
(enrollment: journal minimized, verification authorities, the remaining enrollment plan tests), **R2-B** (issuer
registration and retirement facts persisted), **R2-C** (binding minted at resolve and materialized at step 6;
slots claimed at `bind`; instance query), **R2-D** (one `reissue::eligible`, stable Windows pipe token, mux path
in P, selection feed, ended-grant slot pass, `inspect connections`), **R2-E** (the cross-cutting e2e tests) and
**R2-F** (D5 §6.6's projection-applied switch; the issuer store reason).

| File | What it is |
|---|---|
| `m03-wave4-r2-api.md` | Round-2 ownership map, readings, each worker's landed interfaces, requests. |
| `m03-wave4-r2-questions.md` | Round-2 escalations (integrator status at the top). |
| `m03-wave4-r2-worklog.md` | The integrator's round-2 worklog (integration steps, checks, exit codes). |
| `m03-wave4-r2-worklog-{A..F}.md` | Each worker's worklog with its revert proofs. R2-F was interrupted by a server restart after finishing its fixes; the integrator ran its final checks. |
