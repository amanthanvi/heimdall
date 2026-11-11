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
