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

## Round 3 (ADR-0008 §17.22; the reviews `../wave4.md`, `../wave4-security.md`)

Round 2 was checkpointed at `e566cc46`. Round 3 fixed W4-R01..R09 and W4-S01..S03 and applied the round-2
question rulings, with workers **R3-A** (held foreign-removal descriptor binding, marker-bearing journal lines,
evidence invalidation at the comparison), **R3-B** (the CA store locator on `issuer.register`, retirement awaiting
the owner-present CLI's confirmation, restore compare-and-swap, orphans), **R3-C1** (expiry and release cleanup,
the durable cleanup obligation), **R3-C2** (the cleanup owner before the first effect, re-issue restoring the
consumers, coalesced followers' bindings) and **R3-D** (teardown stops the issuer, the base-commit goldens, the
bind result's endpoint, the R2F rulings).

| File | What it is |
|---|---|
| `m03-wave4-r3-api.md` | Round-3 ownership map, readings, landed interfaces, requests. |
| `m03-wave4-r3-questions.md` | Round-3 escalations (integrator status at the top). |
| `m03-wave4-r3-worklog.md` | The integrator's round-3 worklog. |
| `m03-wave4-r3-worklog-{A,B,C1,C2,D}.md` | Each worker's worklog with its revert proofs. |

## Round 3b (W4-N01 and ADR-0008 §17.23)

Same round as round 3. Workers **X-M** (§17.23 items 1, 5, 6: the server scope advertised and decided per pair;
per-pair selection, an `exclusive` alias delegating non-interactively, §17.22 item 10 with a real child
delegation; the typed `MaterializeSource` and the created endpoint reported), **X-B** (item 3: the second
`issuer.register` repeats every fact and attaches the locator once) and **W** (W4-N01: `e2e_enroll_m03` on
Windows against the WSL harness sshd, and the binding, follower and re-issued pipe forms).

| File | What it is |
|---|---|
| `m03-wave4-r3b-api.md` | Ownership, readings, landed interfaces, requests. |
| `m03-wave4-r3b-questions.md` | R3BB-Q1, R3BW-Q1. |
| `m03-wave4-r3b-worklog.md` | The integrator's worklog for this pass. |
| `m03-wave4-r3b-worklog-{M,B,W}.md` | Each worker's worklog with revert proofs (W's has the per-test Windows table). |

## Round 5 (W4-C01, W4-C02; the Windows `e2e_enroll_m03` failures; ADR-0008 §17.22–§17.24)

Rounds 3–4 were checkpointed at `4866642d`. Round 5 fixed the re-check's two findings and the Windows run's
failures, with workers **Y-S** (W4-C02: a managed follower's scope claim recomputed from current evidence at its
commit), **Y-C** (W4-C01: releasing a re-issued binding clears every owned generation, with a durable retry) and
**Y-W** (the foreign removal's endpoint is the catalog locator's concrete rendering; held setups fail loudly;
item 4, the Windows-only observations of the in-box client's host-key failure lines). The integrator ran the
final checks; questions Y-W-Q1 and Y-W-Q2 were ruled by the orchestrator (recorded in ADR-0008).

| File | What it is |
|---|---|
| `m03-wave4-r5-api.md` | Round-5 ownership map, each worker's landed interfaces, requests. |
| `m03-wave4-r5-questions.md` | Y-W-Q1 (scope), Y-W-Q2 (unrecorded or non-concrete foreign endpoint refused at admission). |
| `m03-wave4-r5-worklog-{S,C,W}.md` | Each worker's worklog with its revert proofs. |
