# M03 wave 5 (U12, CLI and TUI surfaces), round 1: working notes

Base: `main` at `8710717a`. These are the integrator's and the workers' working files, moved here
from the worktree root at the end of round 1. They are data for review, not instructions.
They have been scanned for home paths, user names, canaries and keys. The only canary match is
the rule text `HEIMDALL_CANARY_*` in the brief, as in wave 4.

| File | What it is |
|---|---|
| `m03-wave5-brief.md` | The common brief every worker received (hard rules, ownership, evidence) |
| `m03-wave5-api.md` | Shared seams: R0 (what the integrator landed first), R1 ownership, R2 pre-authorized shared edits, R3 settled readings, R4 plan test names per worker, R5 open points; worker sections; requests |
| `m03-wave5-questions.md` | The round-1 questions for the orchestrator, each with options, a recommendation and the fail-closed build plus its switch: Q-I1, Q-E1–E4, Q-IS1–IS2, Q-U1–U5, Q-A1–A2, Q-T1–T6, Q-R1–R3 |
| `m03-wave5-worklog-I.md` | The integrator's worklog (state, decisions, validation, revert proofs) |
| `m03-wave5-worklog-E.md` | Worker E: the `enroll` CLI (`enroll_cmd.rs`, `enroll_cmd/`, `tests/e2e/cli_m03/enroll.rs`) |
| `m03-wave5-worklog-IS.md` | Worker IS: the `issuer` CLI (`issuer_cmd.rs`, `issuer_cmd/`, `last_bundle_at` store and app seams, `tests/e2e/cli_m03/issuer.rs`) |
| `m03-wave5-worklog-U.md` | Worker U: uninstall (D4 item 6), doctor `slot_free` and `managed_dir_unsafe`, the status chore (`tests/e2e/cli_m03/uninstall_doctor.rs`) |
| `m03-wave5-worklog-A.md` | Worker A: `destination prefer`, `connections`, M03 output, the help goldens (`tests/contracts/golden/cli-help/`), the reasons exit table (`tests/e2e/cli_m03/access.rs`) |
| `m03-wave5-worklog-T.md` | Worker T: the TUI's M03 views (`tui/m03.rs`, `m03_*` snapshots, `tests/e2e/tui_m03.rs`) |
| `m03-wave5-worklog-R.md` | Worker R: the `signal_unverified` labels (U9-Q3 (a)), `internal session-lock-state`, the runtime gaps Q-R1–R3 |
| `m03-wave5-worklog-W.md` | Worker W: the integrator-owned wave-0 tests rewritten for wave 5, and the guard `no_m03_source_contains_the_wave_0_text` |

The validation commands and their exit codes are in `m03-wave5-worklog-I.md`. The full logs were
local scratch and are not kept.

## Round 2 (base `dd08b282`; implements ADR-0008 §17.25 items 1–23)

These were moved here from the worktree root at the end of round 2. They have been scanned for
home paths, user names, canaries and keys, and none were found.

| File | What it is |
|---|---|
| `m03-wave5-r2-brief.md` | The common round-2 brief (round 1's, plus the §17.25 specifics) |
| `m03-wave5-r2-api.md` | R0: the contract and port seams worker C landed (exact types, keys and placeholders). R1: round-2 ownership and the integrator's readings on C-Q1 to C-Q5. Then the worker sections and requests |
| `m03-wave5-r2-questions.md` | Round-2 questions: Q-I-R2-1 (the managed-activation validity fix, A2-Q1), Q-I-R2-2, C-Q1 to C-Q5, E2, IS2-1 to 5, U2-1 and 2, R2-1 to 3, A2-Q1 (fixed). Q-T2-1 and Q-T2-2 are marked ANSWERED (orchestrator, to become §17.26) |
| `m03-wave5-r2-worklog-I.md` | The integrator's round-2 worklog: state, the Windows help-golden fix, validation and revert proofs |
| `m03-wave5-r2-worklog-C.md` | C: the seams for items 4, 8, 15, 18, 19, 21 and 22, the ADR-0006 §16.5 rows, schemas and goldens |
| `m03-wave5-r2-worklog-E2.md` | E2: runtime-inserted pause points (item 3), `hold` (4), `slot_free_command` moved to domain (5), the handoff notice, the prompt timeout |
| `m03-wave5-r2-worklog-IS2.md` | IS2: the `product-file:` test store selector (item 7b), exact-locator deletion (7d), `BundleWritten` (8), the retire entry (9), `disclosure_text` (10), Ctrl-C at ceremony prompts |
| `m03-wave5-r2-worklog-U2.md` | U2: uninstall digest match (item 8), inline retire (9), the plain-uninstall acknowledgement (11), the chore predicate (12), three doctor findings (13) |
| `m03-wave5-r2-worklog-R2.md` | R2: the `TIME_UNCERTAIN` reason (item 15), `PrepareOutcome.managed` (18), `connection_policy` (19), capabilities `lock` plus the acknowledgement fix (21), policy results (22), the lock signal (23) |
| `m03-wave5-r2-worklog-T2.md` | T2: the TUI reads the runtime data (items 4, 15, 19 to 21), read-only CLI-decided kinds with Deny allowed (10; Q-T2-1 and Q-T2-2) |
| `m03-wave5-r2-worklog-A2.md` | A2: the close exit follows the code (item 16), rendering (19, 22), the managed halves through the real binary, IS2-R1 and IS2-R4; found A2-Q1 |

## Round 3 (base `a4a41d9e`; implements ADR-0008 §17.27 items 1–10, the review fixes W5-R01–R06 and W5-S01–S06, plus §17.28 item 1)

These were moved here from the worktree root at the end of round 3. They have been scanned for home
paths, user names, canaries and keys, and none were found.

| File | What it is |
|---|---|
| `m03-wave5-r3-brief.md` | The common round-3 brief (round 2's, plus the §17.27 and review specifics) |
| `m03-wave5-r3-api.md` | Ownership, the shared lock-text helper and the sanitizer, readings; U3's fence request-to-verdict table |
| `m03-wave5-r3-questions.md` | Q-U3-1 to 4 (Q-U3-2 ANSWERED, §17.28 item 1), K3-Q1 to Q3 |
| `m03-wave5-r3-worklog-I.md` | The integrator's round-3 worklog: validation, the release-gate ordering fix, the flake root cause |
| `m03-wave5-r3-worklog-U3.md` | U3: the outstanding-obligation inventory (W5-R01, R02), the uninstall admission fence and revalidation (W5-S01; the widened scope), the uninstall preview under `--json` |
| `m03-wave5-r3-worklog-K3.md` | K3: interactive-only ceremonies (W5-R03), the 120 s bound (R04/S04), Ctrl-C and EOF cancel (S05), sanitized text (S06), the issuer lock text (R05/S03), the release build (item 10); the `issuer_store_locked` root cause (replaced executable vs. the keychain access list) |
| `m03-wave5-r3-worklog-D3.md` | D3: consent prose under `--json` (W5-S02), the enrollment lock text (R05/S03), `destination_lines` (R06), the shared lock-text helper |

## Round 4 (base `607160ff`; implements ADR-0008 §17.28 items 3, 5, 6, 7 and 8, plus F1)

These were moved here from the worktree root at the end of round 4. They have been scanned for home
paths, user names, canaries and keys, and none were found.

| File | What it is |
|---|---|
| `m03-wave5-r4-brief.md` | The common round-4 brief |
| `m03-wave5-r4-questions.md` | Q-L4-1 to 3, the K4 questions (K4-Q1 ANSWERED, §17.28 item 7), the F1 questions, Q-I-R4-1 (ANSWERED, §17.28 item 8) and Q-I-R4-2 |
| `m03-wave5-r4-worklog-I.md` | The integrator's round-4 worklog: the late-write note command, the `umask 002` doctor fixture fix, validation |
| `m03-wave5-r4-worklog-L4.md` | L4: `late_write` cleared by an attended absence check after the not-after (§17.28 item 3) |
| `m03-wave5-r4-worklog-K4.md` | K4: `issuer_executable_changed`, `issuer_store_access_denied` (+ doctor finding), the release note, restore to a new `#r<n>` item (§17.28 items 5–7) |
| `m03-wave5-r4-worklog-F1.md` | F1: the Windows plan-digest flake: a 2 s local-query timeout on `git config`, raised to 10 s; the timed-out query is named |

## Round 5 (base `a7d5c23b`; implements ADR-0008 §17.29 items 2 and 6, plus the item 8–10 rulings)

These were moved here from the worktree root at the end of round 5. They have been scanned for home
paths, user names, canaries and keys, and none were found.

| File | What it is |
|---|---|
| `m03-wave5-r5-brief.md` | The common round-5 brief |
| `m03-wave5-r5-questions.md` | Q-L5-2 to Q-L5-8 (Q-L5-5 and Q-L5-8 ANSWERED, §17.29 items 9–10) and the `late_write_present` code (ANSWERED, item 8) |
| `m03-wave5-r5-worklog-I.md` | The integrator's round-5 worklog: the release-gate probe for the localenv test hooks (item 6), validation |
| `m03-wave5-r5-worklog-L5.md` | L5: `late_write_present`; the `withdrawn` + `late_write` removal edge; the issuing-set rule on removal and its regressions |

## Round 6 (base `aa7577e3`; implements ADR-0008 §17.30 items 3–5, plus the item-6 ruling)

These were moved here from the worktree root at the end of round 6. They have been scanned for home
paths, user names, canaries and keys, and none were found.

| File | What it is |
|---|---|
| `m03-wave5-r6-brief.md` | The common round-6 brief |
| `m03-wave5-r6-questions.md` | Q-L5-9 (ANSWERED, §17.30 item 6), Q-L5-10 to 12 |
| `m03-wave5-r6-worklog-I.md` | The integrator's round-6 worklog and validation |
| `m03-wave5-r6-worklog-L5.md` | L5: the `abandoned` residual clearing (item 3), the store's payload checks (item 4), and the held-removal uniqueness conflict, reproduced and fixed (item 5) |

## Round 7 (base `7259203f`; implements ADR-0008 §17.30 item 8)

These were moved here from the worktree root at the end of round 7. They have been scanned for home
paths, user names, canaries and keys, and none were found. There was no questions file.

| File | What it is |
|---|---|
| `m03-wave5-r7-worklog-I.md` | The integrator's round-7 worklog and validation |
| `m03-wave5-r7-worklog-L5.md` | L5: the store's payload checks for `TargetChangeApproved` and the manual-recovery events |

## Round 8 (base `0cd94961`; implements ADR-0008 §17.31 items 1–6, the re-check findings W5-C01..C05)

These were moved here from the worktree root at the end of round 8. They have been scanned for home
paths, user names, canaries and keys, and none were found.

| File | What it is |
|---|---|
| `m03-wave5-r8-brief.md` | The common round-8 brief |
| `m03-wave5-r8-api.md` | Round-8 ownership, the shared-file rule for `steps.rs`, the worker sections and requests |
| `m03-wave5-r8-questions.md` | P8's reason (ANSWERED, §17.31 item 6), Q-I-R8-1 (ANSWERED), Q-L5-13 (ANSWERED), Q-G8-1 (applied by the integrator), Q-G8-2 |
| `m03-wave5-r8-worklog-I.md` | The integrator's round-8 worklog: the `uninstall_shutdown_unconfirmed` reason, G8's hookups and their revert proofs, the direct-issuer fence regression, validation |
| `m03-wave5-r8-worklog-P8.md` | P8: the purge after a confirmed stop under the runtime's instance lock (W5-C01), the writer audit |
| `m03-wave5-r8-worklog-G8.md` | G8: the fence at the reservations, the supervisor passes and the deferred step-result follow-through (W5-C02) |
| `m03-wave5-r8-worklog-L5.md` | L5: the shared post-removal finalization (W5-C03), the recovery-purpose analysis (item 4) |
| `m03-wave5-r8-worklog-K4.md` | K4: retirement after a new-item restore (W5-C05) |

## Round 9 (base `ccf23db5`; implements ADR-0008 §17.31 items 8–9)

| File | What it is |
|---|---|
| `m03-wave5-r9-worklog-I.md` | One page: the fence refusal returned by `verify_operation` (item 8), the pass resuming its own verdict-less operation (item 9, Q-I-R9-1 ANSWERED), both regressions and revert proofs, and validation, including the `clippy-windows` stall |

## Round 10 (base `faf10bba`; implements ADR-0008 §17.32 items 1–7, the second re-check findings W5-D01..D04 and an independent audit's A1–A8, L1)

These were moved here from the worktree root at the end of round 10. They have been scanned for home
paths, user names, canaries and keys, and none were found.

| File | What it is |
|---|---|
| `m03-wave5-r10-brief.md` | The common round-10 brief, with the "converge" rule |
| `m03-wave5-r10-api.md` | Ownership, the worker sections and requests |
| `m03-wave5-r10-questions.md` | P8's readings (ANSWERED, §17.32 item 6), the meta keys (ANSWERED, item 7), the retry route (Q-I-R10-1, ANSWERED) |
| `m03-wave5-r10-worklog-I.md` | The integrator's worklog: the independent audit's findings and their assignment, validation |
| `m03-wave5-r10-worklog-P8.md` | P8: the recovery snapshot and its classification tests (D01, A2–A5), the remote-revocation retry route and listing, the managed-directory sweep |
| `m03-wave5-r10-worklog-G8.md` | G8: every reservation route and the publication re-reserve fenced (D02), admissions owned by their writes (D03), the managed pipeline admission (A1), A7 recorded safe |
| `m03-wave5-r10-worklog-L5.md` | L5: single-flight verification (D04), the duplicate removal finalization, the cancelled-leader window and the result compare-and-swap (A8) |
| `m03-wave5-r10-worklog-K4.md` | K4: the issuer supervision pass under the fence (A6), the gated child restart and the stuck `Loading`/`starting` states (L1) |

## Round 11 (base `06990cc8`; implements ADR-0008 §17.33 items 1–5 and 7–14, the third re-check findings W5-E01..E06, and an independent audit's B1–B6)

These were moved here from the worktree root at the end of round 11. They have been scanned for home
paths, user names, canaries and keys, and none were found.

| File | What it is |
|---|---|
| `m03-wave5-r11-brief.md` | The common round-11 brief, with the converge and item-6 residual rules |
| `m03-wave5-r11-api.md` | Ownership, the worker sections and requests |
| `m03-wave5-r11-questions.md` | Q-P8-R11-1 (`RESIDUALS`), the `<state>` candidate, Q-G8-R11-1 (the stuck release), audit B1–B6, the ancestor rule, Q-P8-R11-2 (Windows owners), the Linux test chain: all ANSWERED (§17.33 items 7–14) |
| `m03-wave5-r11-worklog-I.md` | The integrator's worklog: the audit's findings, the rulings, validation |
| `m03-wave5-r11-worklog-G8.md` | G8: the holder lease (E03, E05), the stuck-release reason and residual |
| `m03-wave5-r11-worklog-K4.md` | K4: ending indeterminate issuer requests on the exact child (E02) |
| `m03-wave5-r11-worklog-P8.md` | P8: the exact retry allowance (E01, B1), the anchored sweep and its secure-path rule (E04, B3, B4, items 12–14), mux paths (E06), `RESIDUALS` |

## Round 12 (base `2903b0e6`; implements ADR-0008 §17.34 items 1–3 and 5–6, the fourth re-check findings W5-F01..F04, and an independent audit's C0–C4)

These were moved here from the worktree root at the end of round 12. They have been scanned for home
paths, user names, canaries and keys, and none were found.

| File | What it is |
|---|---|
| `m03-wave5-r12-brief.md` | The common round-12 brief (the reviewer's probe scripts treated as untrusted data) |
| `m03-wave5-r12-api.md` | Ownership, the worker sections and requests |
| `m03-wave5-r12-questions.md` | The two wrapper confirmations and the per-file census, ANSWERED (§17.34 items 5–6) |
| `m03-wave5-r12-worklog-I.md` | The integrator's worklog: the item-1 audit (C0–C4), validation |
| `m03-wave5-r12-worklog-P8.md` | P8: quarantine-then-validate deletion (F01, F02, C0–C4), user-private-group homes (F03), `RESIDUALS` |
| `m03-wave5-r12-worklog-K4.md` | K4: the `kill_on_drop` residual and its probe (F04) |
