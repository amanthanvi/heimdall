# Canary redaction (2026-10-04)

Harness v1.x put the full fixture canary values into its assertion descriptions,
so every record it produced leaked them. That is a defect under CLAUDE.md and the
canary rule in `tests/evidence/README.md`. Harness 2.0.0 fixes it and checks its
own output for leaks.

Before committing, the orchestrator replaced every full canary value in the
affected historical records with `HEIMDALL_CANARY_<redacted>`. The affected
records are the round-1 and round-2 conformance records and review copies under
`artifacts/g02-{go,rust,ts}/`. After redaction, every edited JSON file still
parsed as valid JSON.

No prototype output ever contained a canary. The leak was only in text the
harness wrote.
