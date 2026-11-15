# M03 wave 5, round 9 — integrator note (one page)

Base `ccf23db5`. Binding ADR-0008 §17.31 item 8 (Q-G8-2). Done by the integrator; no workers; no commits.

## Change
- `crates/app/src/operations/enrollment_m03/verify.rs` `verify_operation`: a fence refusal
  (`SERVICE_UNAVAILABLE` / `uninstall_in_progress`, new private `is_fence_refusal`) from
  `run_verification` is returned as the error; it is never recorded as an inconclusive
  verification, so the enrollment's evidence, verdict and hold are unchanged.
- `crates/app/src/operations/uninstall_fence_m03.rs`: debug-only `debug_refuse_next_reservation()`
  (`cfg(debug_assertions)`, like round 8's `debug_pause_next_reservation`; compiled out of release
  builds). It is the only way to force the refusal: since round 8 every route into verification holds
  an admission, and a fence acquisition waits for it, so the path is defence in depth.

## Regression
- `e2e_enroll_m03` `fence::verification_fence_refusal_is_returned_and_changes_no_evidence`
  (`#[cfg(unix)]`, system form, like `supervisor_reverifies_before_freshness_lapses`): a verified
  record; the next reservation is refused; `enroll verify` (presence, the supervisor's unattended
  owner caller) returns the fence refusal; evidence, `verified_at` and hold are byte-equal to before,
  and the state is `verified` or `reverifying` (no verdict).
- Revert (arm disabled): exit 101 (panicked at `fence.rs:364`); restored, shasum OK; rerun exit 0.

## Found while fixing (Q-I-R9-1, for the orchestrator)
After the refusal the record stays `reverifying` with its verify operation open. The re-verification
pass skips records with an open operation (`passes.rs` `reverify_due`), and `enroll reconcile` resumes
only `applied_unverified` applies. Before this fix the refusal was recorded as inconclusive, which
settled the operation. In production the path is unreachable (see above), so nothing is stuck today,
but if it were reached, issuance for the pair would wait (`verified_cas_for_pair` counts `verified`
only). Options:
- (a) the pass resumes its own open, verdict-less verify operation after the fence lifts (the deferral
  rule of §17.31 item 2, applied to re-verification);
- (b) an additive domain event returning `reverifying` → `verified` (and `verifying` →
  `applied_unverified`) with no verdict, used on a refusal;
- (c) leave it as built, since the path is unreachable.

Recommendation: (a). It matches §17.31 item 2 and needs no domain change.

**ANSWERED (orchestrator, 2026-11-13; to be ADR-0008 §17.31 item 9): (a) accepted.** After the fence
lifts, the re-verification pass resumes its own open, verdict-less operation (no domain change; it runs
at most once). Regression: force the refusal, lift the fence, and the pass resumes it exactly once to a
verdict; it fails with the resume removed. Built in round 9 (below).

## Validation
- Run 1 (after item 8): stopped by the integrator when item 9 was ruled (the tree changed).
- Run 2 (after item 9): killed at the 2 h background limit. fmt and clippy passed (exit 0);
  `clippy-windows.sh` made no progress from about 12:10 to 14:10 on a cold `target/x86_64-pc-windows-gnu`
  (the integrator prunes it at the end of each round). No process survived. A standalone retry with a
  20 min bound was also stopped by the harness limit. Cause not found: no lock-wait message, no
  surviving cargo, rustc or zig process.
- Standalone `clippy-windows.sh` (cache warming): exit 0, no warnings; wall 15 min (cargo reported 3m09s).
- Run 3, on the warm target: `check.sh` every step exit 0 (2987 passed, 0 failed, 192 ignored; 16 min);
  `linux-xcheck --workspace` exit 0.

## §17.31 item 9 (built)
- `crates/app/src/operations/enrollment_m03/passes.rs` `reverify_due`: also collects the pass's own
  verdict-less operations (record `reverifying`; the open `enrollment.verify` op is the supervisor's
  principal and `reverify_` request namespace; no verification entry reserved) and resumes each with
  `verify_operation`. `reverify_pass` still returns early while the fence is held, so the resume
  happens only after the fence lifts. A resumed run reserves, then settles, so it runs at most once.
- Regression `e2e_enroll_m03` `fence::refused_reverification_is_resumed_once_after_the_fence_lifts`
  (`#[cfg(unix)]`):
  - forced refusal → `reverifying`, op open, 0 entries;
  - fence held → nothing resumed;
  - lifted → `done == [id]`, `verified`, fresher `verified_at`, one reservation per purpose
    (a run reserves 2 entries, each purpose once), op settled;
  - a later pass reserves nothing more.
- Revert (resume removed): exit 101; restored, shasum OK; `fence::` 7 passed.
