# Progress

**Current milestone:** M00 — evidence baseline and gate experiments
**Owner decision pending:** none yet. The G02 language decision and the batched questions come at the end of M00.

| Task | Status | Notes |
|---|---|---|
| M00-T01 current-state note | verified | `docs/current-state.md` |
| M00-T02 source pins + support matrix | implemented_unverified | Committed in d096a64. Reproducible pins; review findings fixed but the fixes have not been re-reviewed. Owner items E6 and E8 |
| M00-T03 disposable SSH fixtures | verified | Committed in 2272e74. Rows 1–5 verified; native-platform rows blocked |
| M00-T04 G03 Windows/WSL | implemented_unverified | Committed in 8418dc9. Two review rounds resolved. Every native record is blocked (no Windows 11/WSL2 host) |
| M00-T04 G04 managed credentials | implemented_unverified | Committed in b44c312. Experiments verified (mechanism level). Recipe B1 pending. Lock probes blocked on owner |
| M00-T05 G02 language/TUI + ADR | in_progress | Prototypes committed (Go 8bc175e, Rust 507215e, TS 0bd7df9). ADR-0002 drafted; round-3 harness coverage and final verdicts running (wf_37282f1c-f61); independent ADR review running |
| M00-T06 release contract etc. | implemented_unverified | Committed in 18bb8df |

## Decisions recorded by the orchestrator

- 2026-10-03: G02 contract clarifications K1–K12 (`docs/g02/slice-contract.md` §9).
- 2026-10-03: gate-probe status convention (`tests/evidence/README.md`).

## Blockers

- No native Windows 11 / WSL2 host. This blocks every G03 native probe and Windows artifact execution.
- Owner-driven macOS screen lock, logout and reboot cycles block the G04 lock probes.
- An owner pain-point list blocks the ADR-0001 baseline-friction worksheet.

## Resume notes

- Workflow results so far are in `tests/evidence/artifacts/m00-wf{1,2,3,4}/`.
- Round 3 (wf_37282f1c-f61) changes no prototype code. It adds harness checks K6d, K6e and K17, has an independent reviewer try to defeat them, then runs the final conformance on darwin and linux for all three candidates.
- When it finishes, commit the harness (tests/g02, fake-agent), the conformance records, the measurements (tools/benchmarks, g02-measurements), the review-g02-harness* artifacts, and the m00-wf* results. Then fill in ADR-0002 §4.
- `tools/benchmarks/g02/run_round2.sh` contains an absolute home path. Redact it before committing.

## Next actions

1. Wait for round 3 (wf_37282f1c-f61): harness K6d/K6e/K17, the reviewer's attempt to defeat it, and the final conformance runs on the unchanged round-2 artifacts.
2. Round 3b (fairness, from ADR review M1–M3). Go's shared-mode signal choice was made before K6b, K6d and K6e existed, so Go gets one fix round under those rulings, plus the terminfo bound and the K10 panic exit code. Rust gets an equal round for any new-check failures and its §4 thread-spawn orphan. For TS, research only: can compiled Bun binaries disable BUN_OPTIONS, BUN_INSPECT and BUN_BE_BUN, and do musl targets exist (review M5). Then the final conformance runs and fresh targeted reviews.
3. Rewrite ADR-0002 against every finding in `tests/evidence/artifacts/review-adr-0002/review.md` (M1–M6, m1–m14), then present the decision package.
