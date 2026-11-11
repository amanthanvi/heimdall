# M03 wave 4, round 2 — worker R2-A (enrollment) worklog

## Goal
ADR-0008 §17.21 items 4 (journal minimized), 5 (verification authorities, each with its own
predicate; `enroll_reconcile_applied` expects `verified`), 11 (the enrollment plan tests listed in
the R2-A row of `.m03-wave4-r2-api.md`).

## Decisions
- R2A-D1 (item 4). `InspectFact` stores the registry's length + SHA-256, the parsed metadata, the
  lock and only the lines containing the record's marker (`StoredReading`); `IssuedStep` keeps the
  remove's pre/post-images by digest. The post-write checks take digests (`ImageDigest`, registry
  crate, pure). The full bytes a removal's post-image needs stay in process memory only
  (16 operations, digest-checked); without them (restart) the removal inspects again ("re-inspect").
- R2A-D2 (item 5). One `verification_authority` per verification kind (Presence = wave 0's
  stored-request rule, SystemAbsence, ApplyInitial, TargetChange). Authorization reads the decision
  record (approved, naming this operation; for a target change also the enrollment, the record's
  approved target and the journal's proposed target). Stage = op state + record state/form + receipts
  + no other open enrollment op of the record (the manual `enrollment.remove` excepted for absence).
  The integrator's shared stage list (any kind at `removal_verifying`, any kind at `outcome_unknown`)
  is gone.
- R2A-D3 (driver fixes found by the plan tests):
  - `fence` used the fence step's own token as the lock token, so every real fence answered `busy`
    (exit 40) and no reconcile could ever fence: now the uncertain step's token, the fence step
    keeping its own step token.
  - reconcile `Applied` (append) and manual-recovery "line present" write the `enroll.append`
    `Confirmed` receipt (D5 §6.7 "Confirmed, then applied_unverified"); the apply's authority needs it.
  - `enroll verify` from `applied_unverified` with a lapsed open `enrollment.apply` settles that apply
    (`DECISION_STALE`, `approval_lapsed`, effect applied), so the verify is the record's only op.
  - re-verification pass: a verified pair whose evaluator no longer finds the approved key is
    re-verified at once with the approved pins (R2A-Q1, switch `HOST_KEY_CHANGE_PROMPT_REVERIFY`,
    at most once per `reverify_prompt_delay`).
- R2A-D4 (tests). Fence tests plant a real holder-recording lock on the scratch registry, held by a
  `/bin/sleep` child of the test leading its own process group (reaped by a thread; stopped by its
  exact `Child` handle); the start identity is computed as the scripts read it (`LC_ALL=C TZ=UTC0`).
  `fence_audit_keeps_signals_sent_on_unproven`: the first fence is real (alive), the terminating
  run's result is reported by the test's CLI loop (exit 44 after `TERM,KILL`): the real script
  reaching unproven after signals needs U5's pause hooks. `rotation_two_accounts_one_unreachable`
  uses two destinations (two loopback sshds) with the same OS account: a non-root sshd
  authenticates only its own account, so the two pairs differ by destination.

## Progress
- [x] item 4  - [x] item 5  - [x] item 11 tests (all 15 listed; none deferred)

## Commands (exit codes)
- baseline `cargo test -p heimdall --test e2e_enroll_m03`: 0 (42 passed).
- after the changes `cargo test -p heimdall --test e2e_enroll_m03`: 0 (60 passed).
- `cargo test -p heimdall-runtime --test model_operations_m03 --test integration_issuer_m03`: 0 (37 + 17).
- `cargo test -p heimdall-registry`: 0 (lib 24, model_registry_pure 17, doc 0).
- `cargo test -p heimdall-enroll`: lib 13 / integration 76 (172 ignored) / verify 51 passed; doctest
  exit 1 on `extern location for heimdall_app does not exist` (another worker's concurrent rebuild
  removed the rlib mid-run; re-run below).
- `cargo test -p heimdall-app --lib`: 0 (49 passed).
- Revert proofs (`/tmp/r2a-revert.py`: revert in place, run the regression, restore, `cmp`, run
  again): see "Revert proofs" below.
- re-run `cargo test -p heimdall-enroll --doc`: 0.
- `cargo clippy -p heimdall-app -p heimdall-domain -p heimdall-enroll -p heimdall-registry --all-targets -- -D warnings`: 0 (no `--no-deps`).
- `cargo clippy -p heimdall --test e2e_enroll_m03 -- -D warnings`: 0.
- `bash tools/validation/linux-xcheck.sh -p heimdall-app`: 0.
- `cargo fmt --all --check`: my files clean (`rustfmt --edition 2024` on them); remaining diffs only in
  `crates/app/src/operations.rs` (not mine).
- final: e2e_enroll_m03 0 (60 passed); runtime model_operations_m03 + integration_issuer_m03 0 (37 + 17);
  registry + enroll 0.
- No `/bin/sleep 300` holder left (checked by PID/PPID/comm); scratch `/tmp/r2a-*` removed. `./target`
  is 67 GB, shared by the four workers: not pruned by me (others are building).

## Revert proofs (each: fix reverted in place → regression run → restored, `cmp` identical → run)
| # | Fix reverted | Regression | Reverted | Restored |
|---|---|---|---|---|
| R1 | `StoredReading::of` keeps the full content | `journal_never_stores_foreign_registry_bytes` | 101 | 0 |
| R2 | apply authority ignores the decision's operation | `verification_authority_apply_initial_needs_its_own_approval_and_stage` | 101 | 0 |
| R3 | target-change authority ignores the decision's operation | `verification_authority_target_change_needs_its_own_decision_and_stage` | 101 | 0 |
| R4 | presence accepted at `removal_verifying` (round 1's shared stage list) | `verification_authority_system_absence_own_stage` | 101 (first run 0: the open manual removal also refused it; test tightened to settle it first, then re-run) | 0 |
| R5 | reconcile `Applied` without the append's `Confirmed` | `enroll_reconcile_applied` | 101 | 0 |
| R6 | fence with the fence step's own token | `fence_unproven_never_unlocks_and_counts_attempt` | 101 | 0 |
| R7 | lapsed apply left open at `enroll verify` | `initial_verification_failure_after_approval_lapsed_holds` | 101 | 0 |
| R8 | `HOST_KEY_CHANGE_PROMPT_REVERIFY = false` | `evidence_invalidated_on_host_key_or_client_change` | 101 | 0 |
| R9 | manual recovery "line present" without the `Confirmed` | `reconcile_after_manual_recovery_classifies_without_redispatch` | 101 (first run 0: no assertion read the receipt; assertion added, re-run) | 0 |
