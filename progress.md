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
| M00-T05 G02 language/TUI + ADR | in_progress | Round 3b: Go and Rust both 136/136 on darwin+linux (harness 2.3.0); TS frozen at 127–128/136. Round 3c running (wf_a7ee1c85-12f): K6e child self-stop, K12 closed-stdout parity, re-measure. ADR rewrite pending |
| M00-T06 release contract etc. | implemented_unverified | Committed in 18bb8df |

## Decisions recorded by the orchestrator

- 2026-10-03: G02 contract clarifications K1–K12 (`docs/g02/slice-contract.md` §9).
- 2026-10-03: gate-probe status convention (`tests/evidence/README.md`).

## Blockers

- No native Windows 11 / WSL2 host. This blocks every G03 native probe and Windows artifact execution.
- Owner-driven macOS screen lock, logout and reboot cycles block the G04 lock probes.
- An owner pain-point list blocks the ADR-0001 baseline-friction worksheet.

## Resume notes

- Workflow results are in `tests/evidence/artifacts/m00-wf{1,...,5}/`. `m00-wf5/` holds round 3 and round 3b.
- Round 3b is done and committed: Go 6a579a9, Rust 94f701f. Both pass 136/136 on darwin and linux under harness 2.3.0, and neither review3 could refute its verdict.
- review3-rust found a major: a child stop (OpenSSH `~^Z`) is not propagated. Contract §9.4 (efbabc0) applies the existing K6e and K12 rules to that case and to closed stdout.
- Round 3c workflow: `wf_a7ee1c85-12f`, script `<session>/workflows/scripts/heimdall-m00-g02-round3c.js`. Stages:
  1. harness 2.4.0;
  2. independent mutation review, plus a fix if needed;
  3. conformance for go/rust/ts;
  4. one fix round, a re-run and a targeted review per failing candidate;
  5. re-measure go and rust.
- Status 2026-10-05 07:50: harness-r4 is done and committed (2.4.0, b224801; result in `m00-wf6/`). A T3 restart at about 00:56 killed review-harness-r4; it was resumed at 07:49 and harness-r4 replayed from cache.
- To resume: `Workflow({scriptPath, resumeFromRunId: "wf_a7ee1c85-12f"})`. Resume can re-run completed agents (seen once). If one re-runs, stop the run and replace that agent with a static object pointing at its saved result.
- `d.env` / `p.env` in the repo root (2026-10-03 16:50, keys PATH and HOME only) are stray env dumps from an earlier session. They are not committed. Delete them at cleanup.

## Next actions

1. Wait for round 3c. Then persist results to `tests/evidence/artifacts/m00-wf6/` and commit the harness, each candidate and the measurements separately.
2. Rewrite ADR-0002 against `tests/evidence/artifacts/review-adr-0002/review.md` (M1–M6, m1–m14) and the round-3/3b/3c results. Get an independent re-review.
3. Present the decision package. Do not start M01 before the owner records D1.
