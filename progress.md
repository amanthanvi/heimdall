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
| M00-T05 G02 language/TUI + ADR | in_progress | Prototypes committed (Go 8bc175e, Rust 507215e, TS 0bd7df9). Harness 2.3.0 committed. Round-3 final verdicts: Rust 136/136 on both OSes; Go fails K6d (both OSes) and K6e (Linux); TS 127–128/136. Round 3b running (wf_915987c9-8cc). ADR draft reviewed (6 major, 14 minor) and awaiting rewrite |
| M00-T06 release contract etc. | implemented_unverified | Committed in 18bb8df |

## Decisions recorded by the orchestrator

- 2026-10-03: G02 contract clarifications K1–K12 (`docs/g02/slice-contract.md` §9).
- 2026-10-03: gate-probe status convention (`tests/evidence/README.md`).

## Blockers

- No native Windows 11 / WSL2 host. This blocks every G03 native probe and Windows artifact execution.
- Owner-driven macOS screen lock, logout and reboot cycles block the G04 lock probes.
- An owner pain-point list blocks the ADR-0001 baseline-friction worksheet.

## Resume notes

- Workflow results are in `tests/evidence/artifacts/m00-wf{1,2,3,4,5}/`. `m00-wf5/` holds the round-3 results: harness-r3, review-harness-r3, final-conf-{go,rust,ts}, ts-research, fix3b-rust.
- Round 3 (`wf_37282f1c-f61`) is finished up to fix3b-rust and ts-research. A T3 restart at 15:44 killed fix3b-go and conf3b-rust-r1. Resuming the old run re-ran fix3b-rust (its cache key changed even though its prompt did not), so it was stopped within a minute (no file edits) and replaced by a continuation workflow.
- Continuation: `wf_915987c9-8cc`, script `<session>/workflows/scripts/heimdall-m00-g02-round3b.js`. Go: fix3b-go (resumes the WIP edits in the tree) → conf3b-go → optional fix → review3-go. Rust: conf3b-rust (fix already done, static) → optional fix → review3-rust. To resume: `Workflow({scriptPath, resumeFromRunId: "wf_915987c9-8cc"})`. If a completed agent re-runs, stop it and replace it with a static object pointing at its saved result.
- Committed: harness 2.3.0 (3263e11); TS final conformance, TS research, measurements, benchmark tools, wf5 results (c051cd5).
- Still uncommitted: Go/Rust round-3b changes and conformance records (being rewritten by the continuation), ADR draft.
- `d.env` / `p.env` in the repo root (2026-10-03 16:50, keys PATH and HOME only) are stray env dumps from an earlier session. They are not committed. Delete them once the owner OKs it, or at cleanup.

## Next actions

1. Wait for `wf_915987c9-8cc`. Then persist its results to `m00-wf5/`, commit Go and Rust separately with their records and reviews, and re-measure Go and Rust if their runtime paths changed.
2. Rewrite ADR-0002 against every finding in `tests/evidence/artifacts/review-adr-0002/review.md` (M1–M6, m1–m14) plus the round-3/3b results. TS research settles M5: the env hooks are confirmed, and musl does exist.
3. Present the decision package. Do not start M01 before the owner records D1.
