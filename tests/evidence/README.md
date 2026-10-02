# Evidence records

One JSON file per acceptance-case or gate-probe attempt, validating against
`record.schema.json` (plan.md §6.6, plus `blocked_on` for blocked records).
Raw, redacted command output lives under `artifacts/<case_id>/`.

Rules: a record for an unexecuted command has `observed_result: null`. A
platform-unavailable test is `blocked` with `blocked_on` naming the platform.
Merged-but-unexecuted code is `implemented_unverified`, never `verified`.
