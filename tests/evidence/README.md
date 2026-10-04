# Evidence records

One JSON file per acceptance-case or gate-probe attempt, validating against
`record.schema.json` (plan.md §6.6, plus `blocked_on` for blocked records).
Raw, redacted command output lives under `artifacts/<case_id>/`.

Rules: a record for an unexecuted command has `observed_result: null`. A
platform-unavailable test is `blocked` with `blocked_on` naming the platform.
Merged-but-unexecuted code is `implemented_unverified`, never `verified`.

## Gate-probe status convention (orchestrator decision, 2026-10-03)

The status vocabulary has no `failed`. Gate probes and experiments (case IDs
`G0x-…`) use it like this:

- `status` describes the evidence, not whether the hypothesis held.
  - `verified`: the probe ran as designed and its raw output is preserved.
    This holds even when the criterion failed.
  - `in_progress`: the probe ran but the evidence is invalid or incomplete,
    for example interrupted or missing a control.
  - `blocked`: the probe could not run here.
- `observed_result.verdict` is required whenever `observed_result` is
  non-null. It is one of `pass`, `fail` or `inconclusive`, and refers to the
  probe's stated criterion.
- A record that names product requirement IDs is never by itself evidence that
  the requirement is met. Harness self-test records carry no product
  requirement IDs.

Acceptance cases (`A01`–`A36`) keep the plan meaning. `verified` means the
pass condition was observed on the stated environment. A failing run stays
`in_progress` or `implemented_unverified`, with expected and observed results.

Multi-row inventory records, such as the fixture inventory, put the
authoritative status for each row in `observed_result.per_fixture` (or an
equivalent per-row map). The top-level `status` is the lowest per-row status
among the rows the record claims to cover.

Canary rule: no evidence record or artifact may contain a full
`HEIMDALL_CANARY_…` value. Harness assertion text names a canary by fixture
and key path, never by value. The prefix alone, used as a scan pattern, is
allowed.
