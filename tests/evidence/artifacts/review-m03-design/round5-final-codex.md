# M03 design final targeted check, round 5 — 07feb280 — ready after fixes (no blocker)

**Reviewer.** Codex GPT-6.1 Sol (`codex-cpamc`, reasoning effort high), independent and read-only, in a separate worktree.
- It ran executable models and a disposable Linux container probe (`python:3.12-slim`, `--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, removed automatically).
- Saved by the orchestrator on 2026-11-06, condensed but faithful in substance.
- Changed files: none.

## Closure
- **R4-01, partly closed.**
  - Closed: pending is checked after an awaited acquisition, through ancestors, and before release. New descendants are marked before round 1 releases its gates.
  - Replays: the reconstructed flood commits at 9.6 s under r5, against 24.6 s under r4. The request whose pre-check came at −0.1 s and whose gate came at 9 s is refused.
  - Still open: the timing proof (R5-01).
- **R4-02, closed in the design.** The augmented state graph has 23 reachable states. All 12 manual-removal starts can reach `abandoned`. None with a `ca_not_held` history reaches `planned`, `withdrawn` or `removed` (ADR-0008:1083).
- **R4-03, closed.** Optional wire fields, their capture points, persistence, replay and golden (plan:2565; ADR-0008:1995).
- **R4-04, closed.** Exit 44 means no unlock and no further signal. Signals already sent stay in `fence_signals`, the result and the audit record. The model `alive → TERM → unproven` keeps the TERM, authorizes no KILL and keeps the lock (ADR-0008:1378; plan:2884).

## Findings

| ID | Severity | Location | Defect | Fix |
|---|---|---|---|---|
| M03-R5-01 | major | ADR-0008:364, 409; plan:495 | Round 1 re-reads the subtree of each root and then revalidates, but the derivation allows only `2 × t_read` for the round; with `r` roots it needs `(r+1) × t_read`. A FIFO reader-writer model (8 roots, 9 grants, a pre-mark delegation releasing at 9.9 s, 2 s reads, no post-mark holder) commits at 29.9 s, while the formula predicts 16.018 s. Enforcing the 20 s ceiling aborts a valid narrowing (Observed in the model). The proof also omits holders: another narrowing keeps its exclusive gates through cleanup (ADR-0008:374), and connection registration holds a shared gate around a store transaction (plan:501). | Re-derive the bound from the actual subtree reads and every shared and exclusive holder; specify and enforce the aggregate budgets needed; add deterministic multi-root and overlapping-narrowing countermodels. |
| M03-R5-02 | minor | ADR-0008:1303, 1401, 3392; plan:2890 | Q29's field 5 is right semantically, but the lookup does not inherit the "after the last `)`" rule, so `awk '{print $5}'` would be wrong. Observed in a container where only `comm` changed and the real pgid was 1: for `plain`, whitespace `$5` gives 1 and the suffix parse gives 1; for `has space`, 0 vs 1; for `a ) b ( c`, `(` vs 1. Linux v6.12 `fs/proc/array.c` emits the name before state, ppid and pgrp. | The shared parser finds the last `)`; in the suffix, pgid is token 3 and start time token 20; validate both; add fixtures with spaces and parentheses. |

## Commands (reviewer)
- Read-only inspection: exit 0. Some no-match searches returned 1 or 2.
- `gate_replay.py` and `models.py`: exit 0. They reproduced 24.6 → 9.6 s, the pre-check trace, release-time refusal and the 29.9 s forest counterexample. Foreign reachability, ancestor coverage, delegation refusal, timestamp replay and the exit-44 self-checks all passed.
- The procfs container probe: exit 0.
- Linux v6.12 procfs source and Tokio fairness documentation were fetched (exit 0; one optional man-page URL returned 404).
- Scratch was removed and the git status is clean.
- Not run: builds, the test suite, native fencing.
