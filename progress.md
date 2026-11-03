# Progress

**Current milestone:** M01 exited 2026-11-01 at b89743ae (docs/architecture/m01-exit.md) → M02 (existing-access slice) design in review
**Owner decisions:** delegated to the orchestrator on 2026-10-31 ("I trust your judgement on all of these and the rest of the decisions. Continue until all open items are done and the product is ready for release"). Recorded in ADR-0004: **G02 D1 = Rust + Ratatui**; G04 recipe B1 (ADR-0005); all other open items decided or blocked on a named physical input (below).

| Task | Status | Notes |
|---|---|---|
| M00-T01 current-state note | verified | `docs/current-state.md` |
| M00-T02 source pins + support matrix | verified | d096a64; recheck 5b2c0a3; fix2 + recheck2 3622c56; fix3 + fix4 with recheck3/recheck4 (2026-10-31, Codex: verified): every recheck2 minor closed, drift ledger `docs/sources/drift-2026-10-31.md` (26 claims unchanged, 4 qualifications: S17, S18, S29, S34; S34 reopens a G07 authority-boundary point). Owner items E6 and E8 |
| M00-T03 disposable SSH fixtures | verified | Committed in 2272e74. Rows 1–5 verified; native-platform rows blocked |
| M00-T04 G03 Windows/WSL | implemented_unverified | Committed in 8418dc9. Native Windows 11 and WSL2 runs since 2026-10-06 (36a8751): most records verified; the rest blocked or in progress on a second Windows/Linux account, a disposable distribution or host, or a console operator (`docs/research/g03-windows-wsl.md` §0) |
| M00-T04 G04 managed credentials | implemented_unverified | Committed in b44c312. Experiments verified (mechanism level). Recipe B1 pending. Lock probes blocked on owner |
| M00-T05 G02 language/TUI + ADR | verified | ADR-0002 revision 3 (re-scored, reviewed twice) and its 2026-10-31 recorded decision: Rust + Ratatui (ADR-0004 §1) |
| M00-T06 release contract etc. | implemented_unverified | Committed in 18bb8df |
| M01-T01..T06 deterministic core | verified (M01 exit 2026-11-01, b89743ae) | `docs/architecture/m01-exit.md`; records A06, A07, A17-local and A19 are verified. A08 and A29-local are blocked only on M04 native sleep/logout/reboot and the second Windows account. 8 independent code-review rounds; the last one says ship |
| M02-T00 design | verified (design gate closed 2026-11-01, 9c458501) | m02-plan.md and ADR-0007 rev 5; 4 independent design reviews, all findings ruled and applied |

## Owner decisions under delegation (2026-10-31)

ADR-0004 records every decision. Still blocked on a physical input only the owner has:
- an operator at the console for logout/reboot probes and for observing a UAC prompt (P-A06); screen-lock probes may run when the console has been idle ≥ 15 min (ADR-0004 §2);
- one elevation consent to create a disposable second Windows account (P-W05, P-W06 cross-user, P-B11);
- a disposable 1Password account (P-W10) and a disposable Windows host (P-W11);
- Apple Developer membership for Developer ID signing and notarization (G04 D3, ADR-0002 Q-F).

## Worklog (current)

- Goal: release-ready V1 candidate (plan §10), all open items done; publishing stays a separate action (plan §10.3).
- Done 2026-10-31: ADR-0004 (delegated decisions), ADR-0005 (recipe B1; three Codex review rounds, accept), ADR-0006 (G08 baseline) + Rust workspace skeleton f5616784; X4 Windows stores verified; G03 P-B08/09/10 verified.
- M01 wave 1 ran as workflow `wf_244d841f-7b7` (U1 contract tests, U2 authority, U3 time, U4 store, U6+U7 Unix IPC + signing framer, U6w Windows pipe tested on the PC) + integrator.
- Design review done (Codex, `tests/evidence/artifacts/review-m01-design/`): proceed after fixes, 1 blocker (time model: boot-scoped continuous budgets, high-water, reboot sync) + 8 major (expired-key markers, attended confirmation decisions, binding/snapshot store APIs, recovery intent/receipts, issuance substrate, OutcomeUnknown settled-vs-final, event snapshot/replay/live, test harness wiring) + 1 minor (hello required ⊆ negotiated). Orchestrator rulings as summarized in the 2026-10-31 thread; applied by a design-fix round after wave 1, before U5.
- Wave 1 committed bae96744 + 78c701cc (implemented_unverified; check.sh 0, 253 tests).
- Design-fix round M01-T00-design-fix integrated (implemented_unverified):
  - What went in: the review's blocker and majors, escalations E1–E15, and rulings R1–R8 (ADR-0006 §13.2) plus the §13 questions (§13.3).
  - check.sh 0 with the test-discovery step: 308 tests, no 0-test target.
  - Store migration 0002 (SCHEMA_VERSION 2).
  - Windows pipe SDDL owner = the creating process's SID. Natively the first run exited 101 (ERROR_INVALID_OWNER) and the second exited 0 (`tests/evidence/artifacts/m01/u6w-native/r6-owner-sddl{,-2}/`). The cross-user case is blocked on the second Windows account.
- Design-fix round committed as f9ed3454.
- Codex design re-review round 2 at f9ed3454 (`tests/evidence/artifacts/review-m01-design/round2/review.md`): proceed after fixes.
  - F02, F04, F05, F07 and F10 are resolved. F01, F03, F06, F08 and F09 are partial.
  - New findings: N01–N04 and N06 major, N05 minor.
  - I checked N01 (shorten drops the tolerance margin) and N05 (reboot below the high-water mark accepted) against the code: both are real.
  - Rulings (in the fixer's brief; it records them in ADR-0006 §13.4):
    - every widening action and every added authority goes through a decision record;
    - the client gets an explicit y/N confirmation;
    - the reboot check is strict;
    - the full issuance predicate applies at reserve and at publish;
    - an oversized event ends the subscription at the last delivered cursor;
    - the fake adapter gets a durable effect ledger, for service-death A06.
- Fixer M01-T00-review2-fix is done (implemented_unverified; check.sh 0 on the shared checkout). N01–N06 are applied, and the rulings are recorded in ADR-0006 §13.4.
- My rulings on the fixer's three questions are in ADR-0006 §13.5 and the m01-plan U5 notes:
  - every ancestor must be issuable, and a delegated child holds an owned reference on its parent;
  - generation is compared with the last validated generation, with automatic re-validation;
  - extensions come from the resolved scope.
- Wave 2 (workflow `wf_11ee3572-cd2`, 12 agents, all completed) and the round-2 fixes are committed as ea074b8b (implemented_unverified).
  - My own check.sh run: exit 0, 513 passed, 0 failed, 1 ignored (the launcher child entry). The 7 m01 records validate against the schema; all are `in_progress`.
  - Native runs: Linux devbox ran all 21 test binaries, all passed, but on a build from before the gap fix. Windows ran on an earlier build. vps1-edge is blocked: Tailscale SSH policy refuses the configured user.
  - The critic found G01–G18. The gap fix closed all but G09 (Windows service-level runs), G14 (records not tied to a commit) and G15 (attendance order).
  - Rulings on the wave-2 escalations: ADR-0006 §13.6.
    - A pause blocks only new activations and bindings (POLICY_PAUSED). This corrects a stricter reading.
    - Pending decisions after an unrelated generation change: strict DECISION_STALE.
    - The child's parent reference is also dropped at `revoking`.
    - N06 can be proven in-process for M01, with jitter required.
    - Policies are merged fail-closed.
    - A later cutoff is widening.
    - The CLI sends Attend first.
    - New `Request::Shutdown` (`service-control/1`), with Windows runtime tests run natively.
- Rulings committed as 93c60d3b.
- Code reviews:
- Codex code reviews of 93c60d3b are done (`tests/evidence/artifacts/review-m01-code/area-{a,b,c}.md`). All three say "fix first".
  - A: 7 majors and 1 minor, reproduced with probes.
    - A01: publish uses a stale time observation.
    - A02: commit is admitted under TIME_UNCERTAIN.
    - A03: prepare runs after the deadline.
    - A04: an unmet offline minimum still reports ACCESS_READY.
    - A05: a failed event catch-up skips an event.
    - A06: a fresh decision reuses the old delta.
    - A07 (minor): duplicate approval records.
    - A08: pause revalidation, covered by §13.6 item 1.
  - B: 4 majors and 2 minors.
    - B01: the harnesses `rm -rf` non-exclusive scratch directories.
    - B02: a stale cleanup retry causes a zero-delay loop.
    - B03: the Windows IPC harness masks a later suite's failure.
    - B04 (minor): sleep detection waits for the next tick.
    - B05 (minor): a pipe-name buffer length is given in bytes, not UTF-16 units.
    - B06 (minor): the unsafe inventory is incomplete.
    - B07/B09 (majors) and B08 (minor) are covered by §13.6.
  - C: 2 majors and 1 minor.
    - C01: a JSON usage error returns no envelope.
    - C02: the evidence generator loses wildcard coverage when a target is missing.
    - C03 (minor): a nonzero exit does not block `verified`.
  - The reviewers confirmed sound: the idempotency, decision-completion, recovery, IPC permission, framing and exit-code paths.
  - Fixes for all of these start once the §13.6 workflow finishes, because they touch the same files.
- The §13.6 rulings are implemented (workflow `wf_c0198760-330`) and committed as 452fcbd4. My check.sh run: exit 0, 541 passed, 0 failed, 1 ignored. The native Windows run 2 exited 0 on an uncommitted tree; run 1 found that inherited stdio handles hung the detached runtime, and that is fixed. ADR-0006 §13.6 items 10–11 are recorded.
- The code-review fixes (workflow `wf_886acd0c-ce2`) are committed as 10414f10. My check.sh run: exit 0, 576 passed, 0 failed, 1 ignored.
  - Every finding has a red-at-base test.
  - B05's Windows unit test and the B01/B03 harness changes are not yet run natively.
  - ADR-0006 §13.7 records my rulings on the fixers' escalations. ADR-0005 §3.5 has an amendment for the re-reservation ordering.
- Running:
- Codex fix-delta re-review at 10414f10 (`tests/evidence/artifacts/review-m01-code/round2.md`): fix first.
  - A01–A04, A06, A08, B01–B08 and C01–C03 are fixed. A05, A07 and B09 are partial.
  - New findings:
    - R01 (major): a re-reservation is published before the issuer signs it.
    - R02 (minor): a shared-approval wait is multiplied by the number of waiters.
    - R03 (major): retention can silently drop a held-back event.
  - R04–R09 are the §13.7 items now being implemented.
  - Next: fix R01–R03, then a targeted round-3 re-check.
- The §13.7 items are implemented (workflow `wf_b2f9242d-155`) and committed as c0af11a6. My check.sh run: exit 0, 595 passed. Migration 0003 sets SCHEMA_VERSION 3. The ADR-0006 §13.8 rulings are recorded.
- Running: workflow `wf_a33d445a-5c2`, the §13.8 rulings, with three fixers:
  - H1, operations: R01 issuer re-reservation, R02 one wait bound per request, terminal transitions for withdrawn authority, and creator cancel after approval;
  - H2, events: R03 retention-gap resync;
  - H3, runtime: descriptor hygiene for the intermittent concurrent-start hang.
  - The integrator runs check.sh twice, to catch flakiness.
- The §13.8 work is committed as 01747a6b.
  - The integrator's two check.sh runs were identical: 620 passed, 2 ignored.
  - I pruned target/ from 19G to 0 and ran check.sh from a clean build: exit 0, 620 passed. target is now 3.2G.
  - The macOS descriptor leak was reproduced at the base (7 hangs in 60 runs) and is fixed.
  - The ADR-0006 §13.9 rulings are recorded:
    - under uncertain time, only the continuous budget expires a grant;
    - re-validation takes its context from the grant;
    - interrupted withdrawals complete;
    - the Windows handle-list residual moves to M04.
- Running:
  - the Codex code review round 3 at 01747a6b, writing to `review-m01-code/round3.md`;
  - workflow `wf_0b82e5b5-9e6` for §13.9 items 1–4.
- Codex code review round 3 at 01747a6b (`review-m01-code/round3.md`): fix first.
  - R01–R09 are all fixed.
  - S01, S02, S03 and S05 are the §13.9 items 1, 2, 3 and 4. S01 and S02 were reproduced with probes.
  - S04 is new (minor): the descriptor-hygiene fallback scan is partial but still reports success.
  - My S04 ruling: scan up to the hard limit if it is finite and at most 1,048,576; otherwise return an error, so spawn and startup refuse.
  - Delegated as M01-review3-S04 (Claude Opus 5.5, shared checkout, platform.rs scope).
- §13.9 items 1–4 (workflow `wf_0b82e5b5-9e6`, migration 0004, SCHEMA_VERSION 4) and S04 are committed as 2142c81a. My check.sh run: exit 0, 637 passed, 0 failed, 2 ignored. The ADR-0006 §13.10 rulings are recorded:
  - the grant origin is a column;
  - a missing mechanism makes the grant degraded instead of ending it;
  - revoke-sweep retries use bounded jittered backoff;
  - the case index covers r136–r139.
- §13.10 items 2, 3 and 5 (workflow `wf_e4d70f86-2c6`) are committed as ca21d621, with the §13.11 confirmations. My check.sh run: exit 0, 652 passed, 0 failed, 2 ignored.
- Running at ca21d621, both at once:
  - task M01-evidence-ca21d621: macOS check.sh, Linux devbox via run-linux.sh, the Windows PC via run-windows.sh plus the windows-ipc harness, regenerated m01 records, a redaction scan;
  - Codex code review round 4 of 01747a6b..ca21d621, writing to `review-m01-code/round4.md`.
- Round 4 is done: fix first.
  - S01, S02, S04 and S05 are fixed. S03 is partial.
  - New, both reproduced with probes:
    - T01 (major): a failed completion commit bypasses the remote-revocation retry cap.
    - T02 (major): removing the original adapter falsely completes a pending remote revocation.
  - Rulings in ADR-0006 §13.12 (not committed yet; the evidence run is building ca21d621 in the main checkout):
    - T01: claim a round durably before calling the adapter.
    - T02: track each obligation per adapter. A missing adapter leaves it pending and visible (adapter_unavailable).
  - Fixer M01-review4-T01-T02 is running in its own worktree, from ca21d621.
  - After it: apply its diff, validate, commit, re-run the native evidence at that commit, and run a round-5 check.
- Native evidence at ca21d621 (`tests/evidence/artifacts/m01/exit-ca21d621/`):
  - macOS 652 passed, 0 failed, 2 ignored (check.sh 0); Linux devbox 587/0/2; Windows 11 546/0/1. Every script, step and binary exited 0.
  - The Windows-only B05 test ran natively.
  - Records: A06 and A07 are verified. A08, A17-local, A19, A29-local and the exit claims are in_progress, because 8 Unix-only tests are absent on Windows (no failures).
  - Ruled in §13.12 item 4: those 8 are marked platform_only; the Windows owner-only ACL check moves to M04.
  - The validator (`minischema.validate`) returns errors and never raises, so the earlier one-line checks were vacuous.
  - New check.sh step `evidence-records`, which self-checks. Re-check: 86 records, 0 invalid.
- T01/T02 are fixed: the fixer's worktree diff is applied and committed as d64503f5. My check.sh run: exit 0, 664 passed, 0 failed, 2 ignored. ADR-0006 §13.13 rulings:
  - the adapter identity is stored on the grant origin;
  - every pending answer is tracked;
  - the retry cap is per obligation;
  - interrupted rounds are due immediately.
- Running: task M01-rulings-13-13 (shared checkout), for §13.13 items 1–4, plus the case index (8 Unix-only tests marked platform_only; r1310/r1312 indexed).
- Then, at that commit and in parallel: Codex review round 5 and the final native evidence run. Then the M01 exit record.
- §13.13 items 1–4 and the case index are committed as b933d3eb.
  - I pruned target/ (9.5G to 0) and ran check.sh from a clean build: exit 0, 675 passed. The 20 mutations were all caught.
  - ADR-0006 §13.14 rulings:
    - the preparing adapter is the only responsible adapter in M01;
    - an effect receipt with the adapter unavailable becomes an adapter_unavailable obligation;
    - the remaining store/domain tests get indexed.
- Running:
  - Codex review round 5 at b933d3eb, writing to `review-m01-code/round5.md`;
  - task M01-rulings-13-14 for §13.14 items 2–3, in the shared checkout.
- Next:
  - integrate those;
  - run the final native evidence at the resulting commit;
  - write the M01 exit record.
- Codex review round 5 (`review-m01-code/round5.md`): T01 and T02 are fixed. U02 (major) is the §13.14 item 2 gap; U01 (minor) is the inspect view overwriting overlapping records.
- Task M01-rulings-13-14 is done (uncommitted): 678 passed, 4 mutations caught. It surfaced an existing intermittent time-property failure: props_rev2 has no fixed seed, and a synchronized reboot with drift −1 is admitted at the true bound.
- My ADR-0006 §13.15 rulings:
  - U02 regression for the reviewer's path;
  - U01: inspect combines every record covering a grant;
  - recovery cleanup never calls revoke for a grant that has a pending record;
  - time property: `sync: true` ⇒ drift 0 (trusted-sync assumption), a named limitation test, a fixed seed.
- Committed as 6230acf9: §13.14 items 2–3, §13.15 items 1–5 and §13.16 (`remote_pending_reasons` is always an array). check.sh exit 0, 686 passed, 0 failed, 2 ignored; 86 records valid. Includes the round-5 review.
- Running at 6230acf9, both at once:
  - task M01-evidence-6230acf9: the final native evidence on macOS, devbox and Windows 11, and the records;
  - Codex review round 6 of b933d3eb..6230acf9.
- If both come back clean: write the M01 exit record, then plan M02.
- Then: validate, commit, final native evidence and a small final review check, then the M01 exit record.
- After that, at one commit and in parallel:
  - native evidence runs (devbox, the Windows PC) and regenerated m01 records;
  - a final Codex check of 01747a6b..HEAD.
  - Then the M01 exit record.
  - Workflow `wf_b2f9242d-155`, implementing §13.7 items 2–6 and 8: G1 authority (items 2–5, maybe a store migration 0003) and G2 evidence/CLI (items 6 and 8), then an integrator.
- After that: native reruns on devbox and the Windows PC from one commit, regenerated m01 records (G14), and the M01 exit record.
- Next:
  - native reruns on Linux and Windows and regenerated records against a commit;
  - fixes for the review findings;
  - then M01 exit, then M02.
- Note for G06: Dependabot reports 4 rustls advisories (1 medium, 3 low) in the disposable X5 evidence lockfile `tests/evidence/artifacts/g02-r4/x5/rust-embed/Cargo.lock`. Production does not use it. An Iroh embedding in M06 must pin a patched rustls.
- If interrupted: resume the workflow from its script in the session's workflows/scripts dir, using resumeFromRunId. Units write only their owner paths (docs/architecture/m01-plan.md).

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
  (reached over the owner's tailnet) is
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

0. **2026-10-31 session (heimdall-27):**
   - Owner rule change: `git push` and use of the owner's SSH config, keys and agent to reach the owner's machines (Windows PC, devbox, vps1-edge) are allowed (AGENTS.md, 218e7417). The repository is public; `main` was pushed for the first time (fast-forward from the initial commit). Older commits still contain the owner's user names, the PC's host name and tailnet address, and one Windows SID (identifiers, not credentials); the current tree is redacted.
   - Done and pushed: G04 P5 v3 real-store run (b5a528cb: unlocked row verified/fail, login measured, limit clause fails again; ran without the D4 confirmation the v1 record asked for, disclosed); X1c post-fix artifacts natively on linux-x64 (972321ce, 139/139 both); X5 Iroh natively on linux-x64 (51413ebb, verified; Windows blocked on Q-G; X5's loopback claim corrected: a transient wildcard-bound UDP socket per endpoint); X1d post-fix artifacts on two Linux hosts without any Go or Rust toolchain (c1327d1e, 139/139 both).
   - M00-T02: fix3 and fix4 with two independent rechecks (Codex GPT-6.1 Sol): verified. New: compare exit 5 (off-pin), GONE class, per-source deadline, word-boundary excerpts, recorded upstream URLs, head-less HTML fix; the 2026-10-31 drift ledger; S34 qualification recorded for G07 (default T3 pairing now includes relay management; a shell/full-access agent can mint a fully scoped session); S29 (OpenTUI now needs Zig 0.17.0) does not affect the frozen TS candidate. The default python3 3.15.2 cannot reach the OpenBSD/OpenSSH sources over TLS; live steps used python3.13.
   - Owner questions now: ADR-0002 §10 D1 and Q-A–Q-G (Q-G new: Iroh on Windows), D3 (k)/(l); D4 coverage of further P5 real-store runs; the rest under "Still open from the owner".
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
   - P5 ran twice, both unlocked, against the real store (one identity each, deleted by exact hash; store empty before and after). Record: `blocked` / fail. Unlocked row `verified` / fail; lock row `blocked`.
     - v1, 2026-10-09 (commits 34ffe3e and 26fed81): fixture login not measured, because of a v1 probe defect.
     - v3, 2026-10-31T20:09:28Z (probe v3 as committed in 34ffe3e; Aqua session; macOS 27.0.1; self-test 132/0 just before): exit 1, run record `verified` / fail. Artifacts: `tests/evidence/artifacts/g04/p5/20261031T200928Z-unlocked/`.
       - Reproduced from v1: the CTK key loads and signs only through `ssh-add -K -S`; export is refused but `sc_auth` exits 0; after delete the agent lists the key but cannot sign.
       - Limit clause (fail, reproduced): a random non-matching `KEYCHAIN_CERTIFICATES` still loads the key, so Heimdall cannot rely on it to select an identity.
       - New: fixture login measured. Certificate login to ca1 through the dedicated agent passed in the setup check and 3/3 samples; the ca2 and no-agent controls were refused. The user-presence flag was not observed (inferred set, because sshd accepted without `no-touch-required`).
       - Orchestrator reports, not archived: the fixture came up at 20:09:20Z on 127.0.0.1 only and `down.sh` exited 0; `sc_auth list-ctk-identities` listed 0 identities afterwards.
   - Remaining for P5: the lock row, which needs the owner at the console (`g04_ctk_probe.sh --mode lock`, v3; it creates and deletes one more identity).
   - Open owner question: does D4 cover further real-store runs, including the lock run? Disclosure: the v3 unlocked run was started without that confirmation, relying on the earlier note here ("The next real-store run creates and deletes one more identity under D4"). The v1 record had said it needed the confirmation. The identity was deleted by exact hash and the store matches its pre-run state.
   - Incident to disclose: the P5 agent ran a bare `ssh-agent` once. It created a socket in `~/.ssh/agent`, and without `-U` it may have removed stale sockets there. The agent was killed by exact PID and its socket removed. It held no keys, and the owner's agent was untouched.
6. M00-T02 is verified (3622c56; fix3/fix4 2026-10-31, see item 0). The recheck2 minors are closed.
   - The record-wording escalations were applied: `g04-windows-*` and `g03-wsl-b-other-windows-user` `blocked_on`; `g03-win-stale-squat-pipe` is now `blocked` under the lowest-row rule. The status order is now written down in `tests/evidence/README.md`.
- Native exit evidence at 6230acf9 is committed as d0c8cb7c (`tests/evidence/artifacts/m01/exit-6230acf9/`).
  - Test counts: macOS 686/0/2, Linux devbox 621/0/2, Windows 11 580/0/1, all exits 0.
  - Every platform row is verified.
  - A06, A07, A17-local and A19 are verified.
  - A08, A29-local and the exit claims are blocked only on M04 native sleep/logout/reboot and the second Windows account.
- Code review round 6: ship M01, no new findings.
- The automated security review of 6230acf9 found a fail-open edge in the cleanup() guard. Ruling ADR-0006 §13.17: skip only for a live obligation; a late effect re-arms or adds one.
- Running:
  - task M01-rulings-13-17, the fix;
  - task M02-T00-design, the M02 architect: docs/architecture/m02-plan.md plus ADR-0007, docs only.
- Next:
  - integrate the fix;
  - native evidence at the fix commit;
  - the M01 exit record;
  - an independent review of the M02 design;
  - the M02 waves.
- The M02 design is committed as f217bb28: docs/architecture/m02-plan.md (U0–U11) and ADR-0007 (D1–D8, proposed).
  - Orchestrator rulings in ADR-0007 §12.1: Q1–Q8 and P1–P2 accepted as recommended.
  - New owner-only input: a disposable macOS user account.
- Running:
  - task M02-T00-design-review, Codex, in a worktree at f217bb28;
  - task M01-rulings-13-17, the cleanup guard fix.
- The §13.17 fix is committed as 8d17ace9 (checkpoint). Fixer-reported validation: check.sh 0 twice, 697 passed. 11 mutations caught.
- ADR-0006 §13.18 rulings (on the fixer's questions):
  - the re-arm bound is per (token, state);
  - only a round claimed after an effect can clear it (inferred race, fail-open);
  - each record stores its cap, and recovery uses min(stored, configured).
- Running:
  - task M01-rulings-13-18;
  - M02-T00-design-review (Codex).
- The automated security review of 8d17ace9 found 3 issues in cleanup():
  - HIGH: an in-flight round;
  - MEDIUM: the re-arm bound key collides;
  - MEDIUM: the bound skips a late effect.
  Rulings are in ADR-0006 §13.18 item 4. They were steered into the running M01-rulings-13-18 task.
- M02 independent design review (`tests/evidence/artifacts/review-m02-design/review.md`): proceed after fixes. 1 blocker (M2-D01, inherited IdentityFile fallback) and 9 majors (D02–D10).
  - Rulings are in ADR-0007 §12.2; every fix is accepted.
  - Running: task M02-T00-design-fix (docs only).
- The §13.18 fixes (round-claim ordering, stored cap, and the 3 automated security findings) are committed as 250a029d.
  - My clean-build check.sh: exit 0, 716 passed, 0 failed, 2 ignored; 86 records valid.
  - §13.18 item 5: the cap is not configurable in M01 production. If it becomes configurable, it must go through OperationsConfig.
- Running, each in its own worktree at 250a029d:
  - task M01-evidence-250a029d, the final native evidence;
  - task M01-code-review-round7, a Codex review of 6230acf9..250a029d.
- Also running, in the main checkout: M02-T00-design-fix (docs only).
- M02 design revision 2 is committed as 8263ee6c (13 units, with U0b for the M01 integration points). The §12.2 rulings are now actually committed: 250a029d's message overstated that.
  - ADR-0007 §12.4: QR1–QR6, P3, P4 and P6 accepted; P5 is a crate or FFI with pinning.
  - New blocked owner input B10: Windows Developer Mode or one elevation, for the A22 Windows symlink row only.
- Running:
  - M02-T00-design-review-round2 (Codex, worktree);
  - M01-evidence-250a029d;
  - M01-code-review-round7.
- Codex review round 7 at 250a029d (`review-m01-code/round7.md`): fix first.
  - W01 (HIGH): a first-round claim identity collides after an explicit re-arm, so an old confirmation erases a newer pending obligation.
  - W02 (HIGH): a durable late confirmation can lose its cleanup across a restart when the operation is already settled.
  - Both reproduced against production libraries. The r1318 property does not exercise real transitions.
  - Rulings, ADR-0006 §13.19: a never-reset claim_seq; the cleanup obligation or intent is written in the same transaction as the late effect, and recovery processes intents for settled operations; a real-transition property.
  - Running: task M01-rulings-13-19.
  - The M01 native evidence at 250a029d (still running) will be superseded. M01 exit waits on the W01/W02 fix, then fresh evidence and a round-8 check.
- M02 design review round 2 (`review-m02-design/round2.md`): proceed after fixes.
  - Resolved: D01, D07, D09. Partial: D02–D06, D08, D10.
  - New: R01–R07 (major) and R08 (medium).
  - Rulings in ADR-0007 §12.5, taking the fail-closed option at each choice:
    - undetermined restores need a new decision;
    - declarations are revalidated before launch;
    - fallback identities on the no-interaction path are refused without the opt-in;
    - --allow-config-commands is required whenever running against the real tree;
    - new requests fail closed until their drivers land;
    - recovery follows a state table, and the final unlink either has its assumption enforced or moves the file to quarantine.
  - Running: task M02-T00-design-fix-2 (docs only), alongside M01-rulings-13-19 (code) and M01-evidence-250a029d (worktree).
- Native evidence at 250a029d is committed as 5de6c82b.
  - Test counts: macOS 716/0/2, Linux devbox 651/0/2, Windows 11 610/0/1. Every platform row is verified; blocked only on M04 and the second Windows account.
  - It is superseded once the W01/W02 fix lands.
- Removed 14 integrated T3 worktrees (about 5.7 GB). The 12 clean ones were removed normally. The 2 with uncommitted work were removed with --force, after verifying every file was identical to, or contained in, the committed versions.
- M02 design revision 3 is committed as d96a9b1c.
  - All §12.5 rulings are applied: a recovery state table, quarantine instead of unlink, fail-closed landing, typed LocalReceipt, per-kind approvals.
  - My rulings in ADR-0007 §12.7: QR7–QR11 and P7–P9 accepted.
- Running:
  - M02-T00-design-review-round3 (Codex, worktree);
  - M01-rulings-13-19, the W01/W02 fixer, editing the main checkout.
- M02 design review round 3 (`review-m02-design/round3.md`): proceed after fixes.
  - R01, R03–R06, R08 and QR3 resolved; R02 and R07 partial.
  - New: S01–S03 and S05 (major), S04 (medium).
  - My rulings, ADR-0007 §12.8:
    - a total recovery function, where an unmatched case is a preserving conflict;
    - content-checked discard;
    - a deterministic Git lock is presumed foreign;
    - honest reporting of config commands;
    - rendered nonsecret target bytes durable in SetupIntent;
    - atomic admission.
  - Running: task M02-T00-design-fix-3 (docs only).
- The W01/W02 fixes are committed as b89743ae: claim_seq, effect_seq, cleanup intents in the settling transaction, a real-transition property at 1024 cases, and visible cleanup_pending.
  - check.sh exit 0, 735 passed, 0 failed, 2 ignored. ADR-0006 §13.20 recorded.
- Running at b89743ae, each in its own worktree:
  - task M01-evidence-b89743ae, native macOS/devbox/Windows evidence;
  - task M01-code-review-round8, Codex.
- Also running, in the main checkout: M02-T00-design-fix-3 (docs only).
- **M01 exited** at b89743ae.
  - Native evidence (`exit-b89743ae/`): macOS 735/0/2, Linux devbox 670/0/2, Windows 11 629/0/1, all exits 0.
  - Every platform row is verified. Code review round 8 says ship, with no findings.
  - Exit record: docs/architecture/m01-exit.md, including the limits carried forward.
- Running: M02-T00-design-fix-3. Then a focused design check, then M02 wave 0.
- M02 design revision 4 is committed as 99e6fc9f.
  - Total recovery function with hold outcome H; content-checked discard; Git lock claimed by a no-replace rename; honest config-command reporting; durable StepContent; atomic admission.
  - ADR-0007 §12.10: QR12–QR15 and P10–P11 accepted.
- Running: M02-T00-design-review-round4. It is focused: S01–S05, totality, and U0b against the current M01 code.
- M02 design review round 4 (`review-m02-design/round4.md`): proceed after fixes.
  - S02, S04 and atomic admission resolved; S01, S03 and S05 partial.
  - New: T01, T02, T04, T06 (major); T03, T05 (medium); and an interface reconciliation list against the M01 exit code.
  - Rulings in ADR-0007 §12.11. Once applied, wave 0 starts. The integrator verifies them against code first, and the wave-0 code review covers them; no further full design review.
  - Running: M02-T00-design-fix-4.
- M02 design revision 5 is committed as 9c458501, and the design gate is closed.
  - Separate Git lock holder K; materialize takes the full step; held fingerprints; RecoveryState; properties over concrete effects; adapter-call timeouts in U0b phase 2.
  - ADR-0007 §12.13: QR16, QR17 and P12 accepted. QR17 carries an M03 retry requirement.
- Running: workflow `wf_ce8d2e38-72a`, M02 wave 0. Stages, in order:
  1. verification against the code;
  2. W0-contract, W0-domain-store and W0-skeleton in parallel;
  3. U0b phase 1;
  4. the integrator, running check.sh twice.
  - Then: an independent code review, and wave 1.
- Incident, M02 wave 0: my SendMessage reply to W0-skeleton (agent ad327f7) resumed it while it was waiting on a background task. Two instances then ran the same packet, and each saw the other as a foreign writer.
  - Told the instances apart: the instance that paused stays read-only; the active one finishes.
  - The wave-0 integrator reconciles anything left inconsistent.
  - Lesson: never SendMessage to a running workflow agent. If coordination is needed, let the integrator stage handle it.
- **M02 wave 0** is committed as d57bf7c4: contract rev 3, frozen interfaces, migration 0005, skeleton crates, CLI tree, U0b phase 1 fail-closed landing.
  - My clean-build check.sh: exit 0, 828 passed (735 M01 + 93 new), 0 failed, 2 ignored.
  - ADR-0007 §12.14 records the rulings on E1–E16 and the integration escalations, including:
    - RecoveryState::build gains a files argument;
    - RestoreCtx::Done carries a cause;
    - IdentitySelectionReport crosses the port in full.
- Running:
  - task M02-W0-code-review (Codex, worktree at d57bf7c4);
  - workflow `wf_71536525-4b6`, M02 wave 1: U1, U2, U7, U6 and U8 core in parallel, then an integrator.
- M02 wave-0 code review (Codex, `tests/evidence/artifacts/review-m02-code/wave0.md`): fix first.
  - Three frozen recovery interfaces disagreed with ADR-0007 §12.14:
    - Z01: RestoreCtx::Done lacked its cause;
    - Z02: the RecoveryState::build argument order was wrong;
    - Z03: StepDecision was in localenv.
  - Everything else was sound: the M01 preserve list, the fail-closed landing, migration 0005, the frozen data contracts, and the duplicate-skeleton tree.
  - I fixed Z01–Z03 myself in bd4215e2, with regression tests. Wave-1 units do not own those files.
- **M02 wave 1** is committed as f704ce93, status implemented_unverified: U1 sshconf parse, U2 eval/render/edit/consent/gitedit, U7 testkit fixtures, U6 adapters and the bounded agent client, U8 core launch.
  - The integrator ran check.sh four times, all exit 0. My own run also exited 0: 1064 passed, 0 failed, 4 ignored.
  - I applied integrator finding B: the production binary takes testkit with default features off.
  - ADR-0007 §12.15 records the rulings. Main items:
    - raw command text in the behaviour digest;
    - source role in the digest (a §5.2 defect);
    - retired keywords ignored, as OpenSSH does;
    - code-loading constructs listed;
    - the §8 SIGPIPE text corrected.
  - Items deferred to wave 3: the PairIntegration report field, clearance against the adopted fingerprint, the provider error mapping, reconcile after restart from PreparedFacts, serde_json for launch, and MAX_ARGV_BYTES.
  - Wave-2 preparation (my commit): sys.rs split into sys/mod.rs (U3) and sys/quarantine.rs (U4a); the localenv→ipc edge, dev-dependencies and seven wave-2 test targets pre-registered as placeholders.
- Next: an independent Codex review of wave 1 (worktree at the wave-2 base), and the wave-2 workflow in parallel.
  - Wave-2 units: W2-U2r (sshconf follow-ups), W2-U3, W2-U4a (primitive), W2-U4b (recovery), W2-U4c (transaction), then an integrator.
- Running (2026-11-01):
  - task M02-W1-code-review: the first run on provider `codex` failed at once on the account usage limit (until Nov 7). The retry on `codex-cpamc` also failed on its usage limit. Final attempt: provider `codex_20237520…` (ChatGPT - Personal 2), same model gpt-6.1-sol, reasoning effort high, worktree, read-only. That failed too (subscription sharing limit). All three Codex instances are out of quota until about Nov 7. The wave-1 review now runs as a fresh-context Claude Opus 5.5 reviewer (claude-cpamc, effort xhigh, worktree, read-only). It is labelled single-model. Owed: a cross-model Codex review of waves 1 and 2 together once a Codex quota resets;
  - workflow `wf_51ee2673-42a`, M02 wave 2, failed: all 6 agents hit Claude 429 rate limits after 1.28M tokens. No unit finished and no file changed; the tree was checked clean at f06a687a. The Claude fallback wave-1 reviewer also hit the rate limit.
  - Cleanup (2026-11-03): removed the failed agents' scratch dirs in /tmp, by exact name; deleted the 3.6G target/ in review worktree t3-25bc06c7. PID 5439 is the owner's own ssh-agent (since Oct 9) and was left alone.
  - Relaunched (2026-11-03):
    - wave 2 as workflow `wf_2a33ac4a-86c`: one retry per unit continuing its partial work; integration skipped when a unit fails, so a resume reruns only that unit; W2-U2r on Sonnet 5.5 to spread the model rate limit;
    - wave-1 review on Codex `codex-cpamc` (retry 3).
  - Dependabot: 4 open alerts (rustls, 1 moderate and 3 low), all in the archived M00 prototype lockfile `tests/evidence/artifacts/g02-r4/x5/rust-embed/Cargo.lock`. rustls is not in the production Cargo.lock. Record this in the M09 release record.
- M02 wave-1 code review (Codex `codex-cpamc`, retry 3; `tests/evidence/artifacts/review-m02-code/wave1.md`): fix first, Y01–Y06.
  - Y01 (high): environment references reuse consent.
  - Y02 (high): the fixture guard checks the shell invocation only.
  - Y03: a quoted Include target is still globbed.
  - Y04: `Match sessiontype` ignores a `SessionType` directive.
  - Y05: a Unix backslash is rewritten.
  - Y06: a Unicode slice panic.
  - Workspace checks passed in the reviewer's worktree: 1071 passed, fmt 0, clippy 0.
  - ADR-0007 §12.16 rules on all six. They are fixed after wave 2 integrates, by one fixer `W2b-fix` (sshconf plus testkit home.rs), because W2-U2r owns sshconf during wave 2.

- **M02 wave 2** (`wf_2a33ac4a-86c`, relaunched 2026-11-03): all 6 agents done, with no API errors this time.
  - Units, all implemented_unverified:
    - W2-U2r: raw command text, source role, retired keywords, code-loading constructs;
    - W2-U3: discovery, passive doctor, probes, Git observation, `adopt_inherited_fd`, `create_owner_only_exclusive`, the `ssh -G` corpus;
    - W2-U4a: the replace primitive, quarantine, materializer;
    - W2-U4b: `RecoveryState::build`, `normalize`, `decide`, `decide_item`, `effects`;
    - W2-U4c: preview, apply, reconcile, the cleaner, the Git lock.
  - Integrator check.sh: 2× exit 0, 1278 passed, 0 failed. No placeholder remains. The only `todo!()` left is `launch::eligibility::check_noninteractive` (wave 3; no callers).
  - ADR-0007 §12.17 rules on the escalations and defines **wave 2b**:
    - W2b-fix: §12.16 Y01–Y06 and §12.17 item 9;
    - W2b-U4r: §12.17 items 1, 2, 4, 7 and the per-row recovery test;
    - W2b-U4t: §12.17 items 2, 3, 4, 5, 6, 8 and 9 — the §5.5 conflict rename, the Git parse check, consent waivers, repair previews, generated domain for GitLock and Removal, and a real process-abort crash test.
  - m02-plan U4: the symlink race test is renamed `…_is_held`.
- Wave 2 is committed as 3e51f49b. My check.sh: exit 0, 1278 passed, 0 failed, 4 ignored.
- Running (2026-11-03):
  - workflow `wf_6f9a053c-b88`, wave 2b: W2b-fix, W2b-U4r and W2b-U4t in parallel, then an integrator that builds a done/partial/not_done table over §12.16 and §12.17. One retry per unit; integration is skipped if a unit fails.
  - task M02-W2-code-review: Codex `codex-cpamc`, gpt-6.1-sol, reasoning effort high, worktree at 3e51f49b, read-only. This is the owed cross-model review, for wave 2.
- M02 wave-2 code review (Codex `codex-cpamc`; `tests/evidence/artifacts/review-m02-code/wave2.md`): fix first, X01–X05. In the reviewer's worktree: 1278 passed, fmt 0, clippy 0.
  - X01 (P1): fd adoption could double-own a descriptor.
  - X02 (P1): a create rollback moved a concurrently edited file.
  - X03 (P1): random markers made first-adoption previews irreproducible.
  - X04 (P2): fresh Git apply ignored a lost K.
  - X05 (P2): DNS outside the probe timeout.
  - ADR-0007 §12.18 rules on all five.
  - I fixed X01 (duplicate via F_DUPFD_CLOEXEC; still safe) and X05 (resolution bounded by the deadline) in the working tree. They are uncommitted until wave 2b integrates, and untested so far, because sshconf is mid-edit by W2b-fix and does not compile yet.
  - X02–X04 go to wave 2c (`W2c-U4`) after wave 2b.
- **M02 wave 2b** (`wf_6f9a053c-b88`): all 4 agents done, with no API errors.
  - Integrator check.sh: 3× exit 0, 1320 passed, 0 failed.
  - Done: every §12.16 item (Y01–Y06) and §12.17 items 1–11.
  - Partial:
    - 8d: `MoveIncludeToTop` takes two operations; accepted in §12.19 item 7;
    - the per-row recovery test runs in memory only; it goes to W2c-rows under §12.19 item 10.
  - The integrator fixed a fail-open in `probe::snapshot` (non-UTF-8 HOME) and added a regression.
  - X01 and X05 (mine): mutation-checked. Removing X01's duplicate makes the test process abort with an "IO Safety violation", the reviewer's defect. Removing X05's bound makes the slow-resolver test fail after 5 s.
  - ADR-0007 §12.19 rules on the wave-2b escalations.
- Next, wave 2c:
  - W2c-U4: §12.18 X02 (create rollback re-checks the active file), X03 (derived markers), X04 (observe K before B_git), and §12.19 item 8 (`verified_client_unavailable` for the Git parse check);
  - W2c-rows: the filesystem-backed `recovery_table_rows_each_have_a_test_vector` (placeholder target pre-registered).
- Wave 2b is committed as 26f94dc8. My check.sh: exit 0, 1321 passed, 0 failed.
- Running: workflow `wf_7ede658e-ecf`, wave 2c (W2c-U4 and W2c-rows in parallel, then an integrator). Base 26f94dc8.
- After wave 2c: a Codex review of waves 2b and 2c (range 3e51f49b..HEAD), then wave 3. Wave 3 is the activation change set, U5 with U0b phase 2, followed by U8 wiring (m02-plan §2).
- **M02 wave 2c** (`wf_7ede658e-ecf`): all 3 agents done.
  - W2c-U4 completed §12.18 X02 (create rollback re-checks the active file), X03 (derived markers) and X04 (live K check before B_git).
  - W2c-rows: the filesystem-backed `recovery_table_rows_each_have_a_test_vector` builds all 80 §5.7 rows on disk (132 + 11 vectors); the in-memory test is renamed `…_each_decide_as_their_row`.
  - check.sh: the integrator ran it twice and I ran it once, all exit 0, 1327 passed, 0 failed.
  - New high finding (integrator probe): without a birth time, a successful Git apply never releases K. Ruled in §12.20 item 1; it blocks the M02 exit.
- ADR-0007 §12.20 rules on the wave-2c escalations and defines wave 3a:
  - W3-U0b: U0b phase 2;
  - W3-U5: drivers and runtime wiring;
  - W3-U4: K release, durable outcome reasons, stale docs.
  - Wave 3b (U8 wiring) follows.
- Wave 2c is committed as 88ac9850. My check.sh: exit 0, 1327 passed.
- Running (2026-11-03):
  - workflow `wf_84d1745b-aed`, wave 3a, the activation change set: W3-U0b, W3-U5 and W3-U4 in parallel, then one integrator. Base 88ac9850.
  - task M02-W2bc-code-review: Codex `codex-cpamc`, worktree at 88ac9850, range 270a8b49..88ac9850. It also re-checks Y01–Y06 and X01–X05.
- M02 wave-2b/2c code review (Codex; `tests/evidence/artifacts/review-m02-code/wave2bc.md`): fix first. In the reviewer's worktree: 1327 passed, fmt 0, clippy 0.
  - Y01–Y06 and X01–X05 re-checked: all closed.
  - New:
    - V01 (high): manual mode skips consent for an active P;
    - V02 (high): consent is evaluated for the shell profile only.
  - ADR-0007 §12.21: fixed in wave 3b by `W3b-consent`, alongside `W3b-U8`.
- **M02 wave 3a** (`wf_84d1745b-aed`), the activation change set: all 4 agents done.
  - W3-U0b, U0b phase 2:
    - decide and drive arms; `setup/1` offered;
    - every adapter call bounded at 30 s;
    - setup cancel;
    - the full identity report; clearance against the adopted fingerprint;
    - provider error mapping; reconcile from PreparedFacts.
  - W3-U5: setup and catalog drivers, runtime wiring, held repairs, consent flow.
  - W3-U4: K released without birth times; durable outcome reasons; `ConflictKind::VerifiedClientUnavailable`.
  - Setup is active end to end through the real runtime: preview → APPROVAL_REQUIRED → approve → apply → inspect → rollback, byte for byte.
  - check.sh: the integrator ran it three times and I ran it once, all exit 0, 1390 passed, 0 failed.
  - ADR-0007 §12.22 rules on the escalations. Wave 3b is now three units:
    - W3b-U8: U8 wiring;
    - W3b-consent: §12.21 V01 and V02, plus §12.22 items 2 and 8;
    - W3b-gaps: §12.22 items 3, 9 and 10.
- Wave 3a is committed as 482c9e70. My check.sh: exit 0, 1390 passed.
- Running (2026-11-03):
  - workflow `wf_4b438985-0b9`, wave 3b: W3b-U8, W3b-consent and W3b-gaps in parallel, then an integrator. The integrator also flips the workspace lint `todo` to "deny" once no `todo!()` is left. Base 482c9e70.
  - task M02-W3a-code-review: Codex `codex-cpamc`, worktree at 482c9e70.
- After wave 3b: wave 4 (U9 CLI and U10 TUI), then wave 5 (U11 exit suite, native evidence on macOS, devbox and Windows, the compatibility matrix), then the M02 exit record.
- M02 wave-3a code review (Codex; `tests/evidence/artifacts/review-m02-code/wave3a.md`): fix first.
  - U01 (P1): cancelling a running held repair reports no effect while the repair continues.
  - U02 (P1): the adapter timeout cannot interrupt the real adapters' synchronous store and filesystem work.
  - ADR-0007 §12.23 rules on both. Wave 3c (`W3c-fix`) runs after wave 3b integrates.
