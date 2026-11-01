# Progress

**Current milestone:** M00 closing → M01 (deterministic core) started 2026-10-31
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
- Running: workflow `wf_886acd0c-ce2`, the code-review fixes. Four fixers with disjoint paths: R1-operations (A01–A04, A06, A07, §13.6 item 11), R1-events (A05), R2-runtime-harness (B01–B05 plus the SIGTERM fallback test) and R3-cli-evidence (C01–C03). An integrator follows.
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
