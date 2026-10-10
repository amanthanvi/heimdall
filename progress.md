# Progress

**Current milestone:** M00 — evidence baseline and gate experiments
**Owner decision pending:** G02 D1. Round 4 and the native Windows/WSL tests are done; ADR-0002 revision 3 recommends Rust + Ratatui (low confidence, conditional on Iroh in V1) and asks Q-A–Q-F (§10).

| Task | Status | Notes |
|---|---|---|
| M00-T01 current-state note | verified | `docs/current-state.md` |
| M00-T02 source pins + support matrix | verified | d096a64; recheck 5b2c0a3 (M1 + m1–m9); fix2 + recheck2 3622c56 (no blocker/major). Open minors n2–n10, n13 (fetcher exit semantics, nits). Owner items E6 and E8 |
| M00-T03 disposable SSH fixtures | verified | Committed in 2272e74. Rows 1–5 verified; native-platform rows blocked |
| M00-T04 G03 Windows/WSL | implemented_unverified | Committed in 8418dc9. Two review rounds resolved. Every native record is blocked (no Windows 11/WSL2 host) |
| M00-T04 G04 managed credentials | implemented_unverified | Committed in b44c312. Experiments verified (mechanism level). Recipe B1 pending. Lock probes blocked on owner |
| M00-T05 G02 language/TUI + ADR | blocked | Round 4 done (X1–X6). ADR-0002 revision 3: re-scored by three blind scorers plus the orchestrator, two adversarial reviews in two rounds. Blocked on owner decision D1 and Q-A–Q-F |
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

1. G02 round 4 (owned by session heimdall-83 since the 2026-10-09 reboot):
   - **X2 done** (101aeeb; `tests/evidence/artifacts/g02-r4/x2/RESULTS.md`). 24 cells, all hidden checks pass, effort equal. Calibrated cross-cell reviews (`t1-calibration/`, `cross-review/T{2,3,4}/`): two causes of an untested major, each in 2–3 of 3 Go cells and no Rust cell (T1 job-control recovery; T3 Bubble Tea wide-character renderer bug), each reproduced independently (`t1-calibration/verify/`, `cross-review/T3/verify/`). History of the three attempts, the excluded contaminated cells and the reruns: RESULTS.md §3 and `runs-excluded/NOTE.md`. Scratch: `~/.local/share/heimdall-m00/r4-scratch/` (x2c-audit, rescore*, review3-*).
   - **Re-score done:** three blind scorers (Codex GPT-6.1 Sol 3.75/3.80, Claude Fable 5.1 3.70/3.90, Claude Opus 5.5 3.50/4.00, Go/Rust) and the orchestrator's pre-registered 3.50/3.90 all lean Rust (`tests/evidence/artifacts/review-adr-0002/rescore-r4/`).
   - **ADR-0002 revision 3 done:** gates updated with native Windows/linux-x64, §7 re-scored (Go 3.50, Rust 3.90; provisional until Q-D), Iroh section from X5, owner questions Q-A–Q-F with a default path, D3 (k) §9.7 batch path and (l) X2 rubric. Review-3: evidence fidelity (Codex GPT-6.1 Sol) and decision logic (Claude Fable 5.1), two rounds each, every finding applied (§13; `tests/evidence/artifacts/review-adr-0002/review-3/`). Also `slice-contract.md` §9.7 and `tests/evidence/g02-{go,rust}-x1b-windows.json` (verified/pass, 71/71).
   - **Next:** the owner answers D1 and Q-A–Q-F. No M01 work before D1 is recorded in ADR-0002 §10.
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
4. ADR-0002 re-score: done (item 1).
5. G04 follow-ups:
   - P5 ran once (unlocked, v1) on 2026-10-09: commits 34ffe3e and 26fed81. Record: blocked / fail.
     - Load and sign: the CTK key loads and signs only through `ssh-add -K -S`.
     - Limit clause (fail): `KEYCHAIN_CERTIFICATES` does not limit which identities that path loads.
     - Export: refused, but `sc_auth` exits 0.
     - Fixture login: not measured, because of a v1 probe defect.
   - Probe v3 fixes the defect and is `implemented_unverified`: self-test 132/0 and software-key rehearsals pass. The next real-store run creates and deletes one more identity under D4.
     - It must run with the screen unlocked; the Mac was locked at 09:23Z, so the run is deferred.
     - The lock row needs the owner at the console.
   - Incident to disclose: the P5 agent ran a bare `ssh-agent` once. It created a socket in `~/.ssh/agent`, and without `-U` it may have removed stale sockets there. The agent was killed by exact PID and its socket removed. It held no keys, and the owner's agent was untouched.
6. M00-T02 is verified (3622c56).
   - Open minors from recheck2: n2 (exit code ignores off-pin), n3 (404 counts as fetch failure), n4 (latent `</head>` normalization), n5, n8–n10, n13.
   - The record-wording escalations were applied: `g04-windows-*` and `g03-wsl-b-other-windows-user` `blocked_on`; `g03-win-stale-squat-pipe` is now `blocked` under the lowest-row rule. The status order is now written down in `tests/evidence/README.md`.
