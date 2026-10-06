# Progress

**Current milestone:** M00 — evidence baseline and gate experiments
**Owner decision pending:** G02 D1, deferred by the owner until round 4 and the Windows/WSL tests (see below).

| Task | Status | Notes |
|---|---|---|
| M00-T01 current-state note | verified | `docs/current-state.md` |
| M00-T02 source pins + support matrix | implemented_unverified | Committed in d096a64. Reproducible pins; review findings fixed but the fixes have not been re-reviewed. Owner items E6 and E8 |
| M00-T03 disposable SSH fixtures | verified | Committed in 2272e74. Rows 1–5 verified; native-platform rows blocked |
| M00-T04 G03 Windows/WSL | implemented_unverified | Committed in 8418dc9. Two review rounds resolved. Every native record is blocked (no Windows 11/WSL2 host) |
| M00-T04 G04 managed credentials | implemented_unverified | Committed in b44c312. Experiments verified (mechanism level). Recipe B1 pending. Lock probes blocked on owner |
| M00-T05 G02 language/TUI + ADR | blocked | Decision package complete: ADR-0002 proposed, re-reviewed, parity-probed. Blocked on owner decision D1 (with D2–D4) |
| M00-T06 release contract etc. | implemented_unverified | Committed in 18bb8df |

## Owner decisions and inputs (2026-10-06)

- **G02:**
  - D1 language: deferred until more research and experiments (round 4) and
    G03 Windows/WSL testing.
  - D2: the owner's personal ergonomics are not a factor; the row becomes
    agentic and open-source maintainability.
  - D3: the orchestrator's rulings stand.
- **G04:** D1–D5 are all yes (new grants under lock; memory-only working key;
  signed macOS bundle; P5 may create and delete a CTK identity in the real
  token store; encrypted offline K_ca backup). Q4 was delegated, and the
  decision is recorded in g04 §9.1.
- **G03:**
  - E-2: default non-exposure is accepted.
  - E-3: the clients are Claude Code, Codex, Pi, Cursor and OpenCode. The
    upstream set is re-asked.
  - E-4: delegated; no packaged client (keep it simple).
  - E-5: delegated; accept and disclose. Recorded in g03 §6.1.
- **Primitives Q1:** accept and disclose (option a).
- **Windows host:** the owner's Windows 11 PC with WSL2 Ubuntu
  (amangamingpc-Ubuntu, 100.66.192.34, reached over the tailnet) is
  available for G03/G02 testing. A dedicated, revocable test key is waiting
  for the owner to install it (the orchestrator does not extract the owner's
  Termius credentials).
- **Cleanup:** `d.env`, `p.env` and the Heimdall `/tmp` residue (1209
  entries) were deleted on 2026-10-06 with owner approval.
- **Still open from the owner:**
  - macOS lock/logout/reboot probes;
  - the SSH pain-point list;
  - E6 (Win32-OpenSSH Preview baseline);
  - E8 (doc snapshots);
  - whether a record that ran everywhere except Windows is `verified` or
    `blocked`;
  - whether synthetic canary-format strings in test inputs break the canary
    rule;
  - the E-3 upstream set.

## Decisions recorded by the orchestrator

- 2026-10-03: G02 contract clarifications K1–K12 (`docs/g02/slice-contract.md` §9).
- 2026-10-03: gate-probe status convention (`tests/evidence/README.md`).

## Blockers

- Windows 11 / WSL2 host: available (owner PC). Access works with a dedicated test key (`from=`-restricted) since 2026-10-06. Probes that need a second Windows account or admin rights are still blocked until authorized.
- Owner-driven macOS screen lock, logout and reboot cycles block the G04 lock probes.
- An owner pain-point list blocks the ADR-0001 baseline-friction worksheet.

## Resume notes

- Workflow results are in `tests/evidence/artifacts/m00-wf{1,...,6}/`. `m00-wf6/` holds round 3c.
- G02 prototype rounds are closed (contract §9.5, 6de1d95).
- Final commits:
  - harness 2.4.2: c07f702
  - TS verdict: 767aeac
  - Go: 38b6b72, 139/139 darwin+linux
  - Rust: d8f0cbe, 139/139 darwin+linux
  - measurements: 97417f7
- ADR-0002 revised after review-2 (a8cf583) and parity probes (§6.1). It is ready for the owner.
- `d.env` / `p.env` in the repo root (2026-10-03 16:50, keys PATH and HOME only) are stray env dumps from an earlier session. They are not committed. Delete them at cleanup with the /tmp residue: `/tmp/hpa*` (~930 dirs), `/tmp/M00-T05-*`, `/tmp/r4fix`, `/tmp/hp-*`, `/tmp/bun-src`, `/tmp/ts-research`.

## Next actions

1. G02 round 4:
   - X3–X6 studies are done and committed. The X2 fairness review found 3 majors (baseline drift, implementer isolation, T1 scoring).
   - The task-pack fix died on a 429 rate limit partway through; its partial work is in `~/.local/share/heimdall-m00/r4-hidden/`, pinned to post-X1b base 84c7665/001a791.
   - Workflow `wf_55ae5a9c-4b4` finished the pack fix, but its recheck found a new major: the transcript audit missed relative/cd/glob access and commands run from the repo root. The run correctly stopped before any implementation.
   - The host disk was full (8.5 GB free). The orchestrator moved the seeded trees into `r4-hidden/seeded-trees/` and deleted `/tmp/hm-r4` (25 GB). About 33 GB is now free.
   - Second attempt: workflow `wf_21d21205-c96` (script `heimdall-m00-g02-round4-x2b.js`).
     - fix2, then recheck2, then workspaces, then 3 batches.
     - Reviewers delete each cell workspace once its evidence is copied (isolation and disk).
     - Decision: T2.ascii_fold_only counts toward all_pass.
   - Afterwards: audit the implementer transcripts with `audit-transcript.py`, compute tokens and tool calls per cell, and commit the specs, runs and the hidden pack copy.
2. X1 is done:
   - G03: commit 36a8751. Windows 9/12 executed; WSL 11 pass, 2 in_progress, 5 blocked.
   - G02 native: commit 48f854a. linux-x64 139/139 for both; windows-x64 Go 63/63, Rust 60/63 gating before §9.6.
   - Contract §9.6 (Windows rulings): 7127b20.
   - X1b Windows fix round is done:
     - Baseline under §9.6: Go 67/71 (batch-file injection), Rust 68/71.
     - After one fix round each: Go 71/71 (refuses .bat/.cmd, 84c7665) and Rust 71/71 (GetFileType checks, 001a791). Both still 139/139 on darwin+linux.
     - Independent reviews found no major in either.
3. Still blocked on the owner, for G03:
   - a disposable second WSL distribution and WSL restarts (P-B08/09/10);
   - a second Windows account (P-W05, P-W06 cross-user, P-B11);
   - a disposable 1Password (P-W10);
   - a disposable host (P-W11);
   - an operator at the console (P-W07 Ctrl-C, P-A06 UAC, P-B07 lock);
   - X4 Windows DPAPI/CNG/TPM, which write to the user key store and the TPM.
4. Re-score ADR-0002 §7 with X1–X6 and get an independent review. Then present the decision (owner D4: after Windows testing).
5. G04 follow-ups: P5, now authorized in the real token store.
