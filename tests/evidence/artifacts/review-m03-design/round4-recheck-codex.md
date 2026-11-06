# M03 design targeted re-check, round 4 — 6674722f — ready after fixes (no blocker)

Reviewer: Codex GPT-6.1 Sol (`codex-cpamc`, reasoning effort high), independent, read-only, separate
worktree. It ran disposable per-shell fencing probes in containers built from official images:
`debian@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308` and
`alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a`. The containers had
no network, were bound to scratch only, and were removed by their exact IDs. The probes also ran on
native macOS. Saved by the orchestrator on 2026-11-06, condensed but faithful in substance. Changed
files: none.

**Verdict: ready after fixes.** Closed: the dash fencing blocker (R3-01), the enqueue order (R3-02),
the gate-order cycle (R3-03's original) and the proposed target (R3-05). Two majors (R4-01, R4-02)
and two implementer-facing minors (R4-03, R4-04) remain.

## Closure of round 3
- **R3-01, closed for safety.** D:1245–1278 requires a successful control that agrees with the
  listing. In every shell, the live-child case was never classified empty. dash, bash as `sh` and
  macOS `sh` recognized an empty group. BusyBox rejects the syntax, so it stays unproven even for an
  empty group: a manual-recovery fallback, allowed by §17.9.
- **R3-02, closed in the design.** D:272–298, P:451.
- **R3-03, original cycle closed.** D:324–340 and Q26's ancestor-chain hold close it, but Q27's bound
  is not established (R4-01).
- **R3-04, original admission omission closed.** D:799–815, 980; P:409–414. The system-form
  lifecycle needs correction (R4-02).
- **R3-05, closed.** D:983–988, 1410–1414; P:1507–1513.

## Findings

| ID | Severity | Location | Defect | Fix |
|---|---|---|---|---|
| M03-R4-01 | major | D:259, 320, 324–361; P:455, 470 | Pending is checked only by the unlocked pre-check, not by the fresh authorization or the release check. A request that passed the pre-check can take a shared gate and sign after the mark. The mark covers only the initial set, and descendants discovered in round 1 stay unmarked. An executable model reached a commit at 24.6 s (beyond the promised 20 s), and admitted a request at t=9 after its pre-check at t=-0.1 despite the mark at t=0 (Inferred from the algorithm; reproduced in the model). | Make pending authoritative at gate acquisition, with a re-check after an awaited acquisition. Cover descendants created or discovered later, e.g. an ancestor-pending check, and extend coverage before round 1 releases gates. Add deterministic tests for both traces. Re-derive the bound. |
| M03-R4-02 | major | D:818, 824–829, 993–996; P:409–414, 2600–2605 | Q28 says an inconclusive foreign record stays listed and can be abandoned, but `manual_removal_pending` has no `→ abandoned`. Its foreign origin is `planned`, so cancel leads `removal_verifying --ca_not_held--> manual_removal_pending --cancel--> planned --cancel--> withdrawn`, which is final with no absence proof (Observed in a graph transcription). | Add an explicit foreign manual-removal abandonment that keeps `pending_until_line_removed`. Make cancel after `ca_not_held` unable to discard that residual. Put both paths in `foreign_removal_paths_golden`. |
| M03-R4-03 | minor | D:3208; P:2480; `contract/src/request.rs:690` | Q27 requires request and commit times in the revocation result, but neither the plan's `RevokeData` nor the current code has them (Observed). | Add both timestamps, their capture points and replay semantics to the frozen contract and its golden. Capture commit time at the tombstone transaction. |
| M03-R4-04 | minor | D:1280, 1324; P:2799 | `fence --terminate` can find `alive`, send TERM, then get `unproven`, and still exit 44, "nothing signalled" (Inferred). | Exit 44 means no unlock, and no further signal is authorized by an unproven decision. Any prior termination attempt is kept in the result and audit data. |

## Per-shell probes (C = `kill -s 0 -- -$$`, K = `kill -s 0 -- -PGID`, L = `ps -A -o pgid=`; exits C/K/L)

| Shell | Live child (leader gone) | Empty group | Invalid syntax | Injected disagreements |
|---|---|---|---|---|
| dash 0.5.12-12 | 0/0/0 live | 0/1/0 empty | 2/2/0 unproven | unproven (3 branches) |
| bash 5.2.37 as `sh` | 0/0/0 live | 0/1/0 empty | 1/1/0 unproven | unproven |
| BusyBox 1.37.0 `ash` | 1/1/0 unproven ("invalid number '--'") | 1/2/0 unproven | 1/1/0 unproven | unproven |
| macOS `/bin/sh` (bash 3.2.57) | 0/0/0 live | 0/1/0 empty | 1/1/0 unproven | unproven |

- The prerequisite `ps -o pgid= -p $$` works in dash, bash as `sh` and macOS `sh`. BusyBox `ps`
  rejects `-p` (exit 1), so a literal script there stops with exit 33 before the control runs.
- An earlier probe with a malformed option made bash-as-`sh` print argument errors yet return 0, so
  diagnostics never imply a nonzero status.
- A genuine same-user `EPERM` could not be produced.
- The disagreement rows are injected faults applied to real command tuples.

## Commands (reviewer)
- Read-only inspection: exit 0.
- Container preparation: an initial Debian image lacking `ps` exited 127; `procps` was then
  installed with the network still attached, and the network was disconnected afterwards.
- Five harness runs: four early failures, described in the record, then a final run exiting 0.
- `models.py`: exit 0, with the R4-01 traces reproduced.
- All containers were removed and no fixture processes were left. Scratch was removed by an exact
  path, and the git status was clean.
- Not run: builds, the production suite, and native Windows/WSL.
