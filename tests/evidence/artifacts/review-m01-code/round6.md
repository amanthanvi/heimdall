# M01-code-review-round6 — `6230acf943711b90de03f9b49ffcbd6ac29e42e7` — **ship M01**

Reviewer: Codex GPT-6.1 Sol (reasoning effort high), independent, read-only, separate worktree.
Saved verbatim by the orchestrator on 2026-11-01.

Independent, adversarial, read-only review of `git diff b933d3eb..6230acf9`, assessed against `spec.md`, `plan.md`, ADR-0005 §3.5–§3.7, and ADR-0006 revision 2 through §13.16.

**U01 and U02 are fixed. No new concrete implementation blocker was found.** Offline workspace validation exited **0**: **686 Rust tests passed, 0 failed, 2 ignored**. Both independently reconstructed round-5 reproductions passed against this checkout's production libraries.

This is a code-review verdict. Formal M01 exit still requires current-head evidence and its completed evidence record.

## U01 and U02 disposition

| Finding | Status | Source evidence and proving tests |
|---|---|---|
| **U01 — overlapping revocation records overwrite inspection status** | **fixed** | `crates/app/src/operations.rs:2085` constructs each record's view; `:2109` combines maximum attempts, latest timestamp, logical AND of stopped flags, and deduplicated reasons. Inspection combines covering records at `:5708`. **`r1315_2_inspect_combines_every_pending_record_that_covers_a_grant`** and **`remote_views_combine_whatever_the_record_order`** passed. Independent scratch test **`round6_overlapping_root_probe`** also passed: it revoked the greater root first, exhausted that record to cap 3, revoked the other root, verified that both records owed the child, and observed `stopped: false` with attempts 3. |
| **U02 — an attempted effect disappears when its adapter is unavailable** | **fixed** | `crates/app/src/operations.rs:2157` checks the durable preparing-adapter origin before consulting effect receipts. `crates/store/src/ext.rs:1156` finds receipts belonging to operations pinning the grant. `crates/app/src/operations.rs:2348` retains an obligation for an unavailable adapter when an effect is recorded. **`r1315_1_an_attempted_grant_failed_by_recovery_without_its_adapter_stays_pending_after_revoke`** passed. Independent scratch test **`round6_attempted_partial_restart_failed_then_revoke_probe`** also passed through the exact sequence: `Attempted` receipt, partial result, `Preparing`, restart without adapters, recovery to `Failed`, then revoke. The result named the grant as remote pending, persisted an `adapter_unavailable` obligation with zero attempts, and kept it visible in inspection. |

## New findings

**None meeting the concrete-failure threshold. No V-series findings.**

The following targeted checks support that conclusion:

- **Effect detection and retention.** `had_effect` conservatively treats the persisted preparing-adapter identity as evidence of an attempted effect. That identity is written with the first `Attempted` receipt in the same transaction at `crates/app/src/operations.rs:4732`, so receipt retention does not erase the evidence for current-format grants. The receipt query filters by the recovery intent's pinned grant. **`grant_has_effect_receipt_reads_only_the_effects_of_the_operations_pinning_it`** passed for attempted, confirmed, uncertain, not-attempted, missing-receipt, and unrelated-grant cases. **`r1313_1_the_preparing_adapter_stays_responsible_after_operation_retention`** also passed.

- **Combined inspection view.** The aggregation preserves pending visibility and follows §13.15's maximum/latest/all-stopped rules. The checked-in overlapping-root test additionally verifies that a reason present in the retryable record remains visible alongside a stopped record. The reasons field is consistently an array, as §13.16 requires.

- **Cleanup ownership.** The guard at `crates/app/src/operations.rs:4871` checks membership in every pending record's `grants`, including ancestor-root records. I traced all four call sites: late confirmation (`:4856`), recheck refusal (`:4983`), commit refusal (`:5241`), and cancellation (`:6520`). The guard itself changes no obligations or counters. The three **`r1315_3_*`** recovery tests passed, covering an own-root record, an ancestor record, and unchanged cleanup without a record. Independent **`round6_live_cleanup_preserves_pending_ownership`** passed for live cancellation and replay after revocation: neither added an untracked adapter call, and the pending record remained.

- **Durable points and recovery.** The new effect predicate runs within the existing first-denial transaction. Local denial and its obligation therefore commit or roll back together; the adapter call follows the durable claim. The **`r1312_*`** and **`r1313_*`** suites passed again, including failed completion commits, interruption after a claim or adapter call, missing adapters, per-obligation caps, and retention. These restart tests reconstruct the runtime in process; they are not native process-crash evidence.

## Time-property assessment

**The generator correction does not hide a demonstrated production defect under the stated truthful-clock assumption. Admission at the true bound with a truthful synchronized clock is refused.**

The decisive check is `crates/domain/src/time.rs:604`: `admission` tests wall-clock expiry before evaluating boot identity or continuous budget. `is_expired` at `:653` uses `now >= deadline`. Consequently, a truthful observation at the bound cannot return `Open`, including before or after re-anchoring.

Observed evidence:

- **`regression_synchronized_reboot_at_the_true_bound_is_not_admitted`** passed.
- Independent **`round6_truthful_clock_at_bound_refuses_in_all_anchor_states`** passed for same-boot, different-boot, and newly anchored grants, including fractional-second bounds.
- The corrected property passed with its default seed and with **16 explicit alternate seeds**, each running 384 generated cases.
- **`a_clock_lying_by_d_while_reporting_synchronized_admits_at_most_d_past_the_true_bound`** passed for errors of 1, 30, and 120 seconds. It requires an actual overshoot approaching the injected error and checks that admission ends before that error is exceeded; it does not pass merely because everything is refused.

The fixed default seed at `tests/model/time.rs:1317` preserves explicit `PROPTEST_RNG_SEED` overrides. Restricting synchronized reboot drift to zero at `:1276` matches §13.15's assumption. The separate limitation test documents the counterexample outside that assumption. It proves the selected traces, not a universal bound for every possible lying-clock history. Native synchronization-signal reliability remains unverified here.

## M01 exit assessment

**Apart from native platform evidence, I found no implementation defect blocking plan §5's M01 exit at this commit.**

There is still an evidence-completion item: `tests/evidence/m01-exit-claims.json:3` remains `in_progress`, and `:16` names `ca21d621`, rather than this head. This review's successful local validation does not refresh that record, its platform rows, or artifact digests. Current-head evidence must be assembled before formally recording M01 exit.

## Commands and observed exits

| Command/check | Exit | Observed result |
|---|---:|---|
| `pwd`; `git status --short`; `git rev-parse HEAD`; active home-instruction read | 0 each | Requested checkout and commit; clean tree. |
| Memory-registry `rg` for Heimdall/M01 | 1 | No matches; no memory used as review evidence. |
| Targeted `git diff`, `rg`, `sed`, `nl`, and `cat` reads | 0 for successful reads | Inspected changed code, contracts, tests, prior review, and exit records. Two exploratory `cat` reads targeted nonexistent files and returned 1. |
| `git diff --check b933d3eb..6230acf9` | 0 | No whitespace errors. |
| `CARGO_NET_OFFLINE=true PYTHONDONTWRITEBYTECODE=1 bash tools/validation/check.sh` | **0** | **686 Rust tests passed, 0 failed, 2 ignored**; formatting, host/Windows-target Clippy, discovery, schemas, stubbed harness self-tests, 25 evidence-generator tests, and 86 evidence records passed. |
| Scratch-suite creation under `/tmp/heimdall-round6-probe` | 0 | Copied fixture suites and added independent probes outside the repository. |
| Initial scratch compilation/setup | operations rustc **1**; time rustc **0**; one setup script **1** | Missing `tempfile` argument, then a dependency-selection error; corrected. |
| Initial scratch operation runs | **101** each | Mixed Cargo feature builds caused Tokio "no reactor running" failures. These were harness-linking failures, not accepted production evidence. |
| Corrected `rustc --edition=2024 --test … -L dependency=target/debug/deps --extern …` compilations | **0** | Linked operation probes against a consistent set of test-build libraries. |
| Scratch operation suite: `round6_`, `r1315_`, `r1314_`, `r1312_`, `r1313_` | **0** each | Final independent probes: 3 passed. Regression groups: 5, 2, 8, and 8 passed respectively. |
| Scratch time suite: `round6_`; `props_rev2`; property with seeds 1–16 | **0** each | Boundary probe, three revised time tests, and all alternate-seed runs passed. Scratch failure persistence was disabled. |
| Validation-log totals extraction | 0 | Confirmed 686 passed, 0 failed, 2 ignored; 86 records, 0 invalid. |
| Required prototype-output `du` command | 1 | No matching prototype output directories. |
| `du -sh target` | 0 | 3.3 GB before cleanup. |
| Guarded removal of checkout `target/`, owned scratch directory, and validation log | 0 | Removed all review build/scratch outputs. |
| Final absence assertions; `git diff --exit-code`; `git status --short`; `git rev-parse HEAD` | 0 each | Outputs absent; checkout clean at `6230acf943711b90de03f9b49ffcbd6ac29e42e7`. |

**Changed files:** None. No commits, pushes, network access, or native remote harness runs.

Not checked: fresh native platform behavior, real credential adapters, or native crash/lifecycle recovery.
Risk: truthful synchronized time remains an explicit assumption; formal M01 closure still needs current-head evidence.

(Orchestrator note, 2026-11-01: after this review, an automated security review of the
pushed commit flagged a fail-open edge in the `cleanup()` guard at `:4871`. The guard
skips the immediate revoke whenever any record lists the grant, even when that record
is stopped (capped) or holds no live obligation for the applying adapter. A late-applied
effect could then stay live. Ruling ADR-0006 §13.17 fixes it after this review.)
