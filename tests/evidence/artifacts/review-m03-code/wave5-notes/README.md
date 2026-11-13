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
