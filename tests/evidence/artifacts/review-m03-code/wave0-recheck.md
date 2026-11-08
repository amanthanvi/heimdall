**Verdict: merge.** R1–R5 are resolved at `6c6b5e064141ca3a38c50b0cad06c0ecfc768394`. No new defect introduced by these fixes was found in the touched code.

Reviewed `87b9a263..6c6b5e06` in the supplied worktree, the original review and probes, main's ADR-0008 §17.16, and the relevant behavior and protocol definitions in `spec.md`, `plan.md`, the M03 plan, and the ADRs. This report is saved at [/tmp/hm-w0-recheck/report.md](/tmp/hm-w0-recheck/report.md).

**Per-finding re-check**

| Finding | Decision and code evidence | Regression evidence |
|---|---|---|
| **R1 — lock-policy change bypasses narrowing** | **Resolved.** `crates/app/src/operations/narrowing.rs:961` classifies `Continue → RevokeOnLock` as narrowing. The reader selects live grants of the applicable profile and includes descendants (`:986–1004`); `policy_commit` uses the full protocol (`:1168–1178`). Widening actions remain decision requests. | `tests/model/narrowing_m03.rs:2895`, `set_lock_behavior_revoke_on_lock_narrows_before_commit`, passes at the fixed head. It holds an admitted permit while the source is locked, verifies the pending mark refuses release, checks the commit waits for the permit, and verifies fresh admission refuses afterward. Restoring the parent's non-cutoff direct-write routing in scratch makes this test fail, **exit 101**: the old permit remains releasable. **The regression detects the original defect.** |
| **R2 — permission removal commits before gating** | **Resolved for the reported removal trace.** `permission_reader` detects removed permission bits and selects the environment's live grants and descendants (`narrowing.rs:1014–1047`). `set_environment_permissions` runs the write through `narrow`, then revalidates affected grants in the same transaction (`:1073–1099`); later withdrawal recovery remains. Production permission writers were searched; no existing production update path bypassing this new entry point was found. | `tests/model/narrowing_m03.rs:2944`, `environment_permission_removal_narrows_before_commit`, passes. It checks that `automatic_activation=false` cannot commit while the old permit is held, that the mark refuses release, and that withdrawal is durable before any tick. In scratch, replacing this operation's set reader with an empty reader bypasses its gate selection while retaining the new API. The test fails, **exit 101**: “the permission removal committed while the old permit could still be released.” **The regression detects the gate-before-write requirement.** This is a targeted mutation, not a literal whole-method reversion, because the parent has no such API. |
| **R3 — overlapping narrowings deadlock** | **Resolved.** `crates/app/src/managed.rs:726–749` records the acquisition targets, clears every exclusive hold before deferring, keeps marks, and restarts acquisition in global order. This implements §17.16 item 3. | The primitive regression at `tests/model/narrowing_m03.rs:3043` and the two-real-policy-cutoffs regression at `:3092` both pass. Restoring the parent's `managed.rs` in scratch makes **both fail, each exit 101**: the first times out taking A; the second times out waiting for both policy commits. **Both regressions detect the original deadlock, including the required growing multi-root Operations trace.** |
| **R4 — authorization latency extends expiry** | **Resolved.** `crates/app/src/operations/authorize.rs:301–315` pairs a Tokio instant with one operations-clock observation before the awaited authorization read, then maps wall and continuous bounds to absolute instants. `:318–319` refuses an expiry reached during that read. No post-await `now + remaining_budget` calculation remains. | `tests/model/narrowing_m03.rs:2832`, `authorization_latency_never_extends_continuous_budget`, passes. It covers a 500 ms commit delay with 500 ms wall lag, release at the original expiry, and admission after the budget expires during the read. Restoring the parent's `authorize.rs` in scratch makes the test fail, **exit 101**: expiry is **500 ms past the original budget end**. **The regression detects the original defect.** The mutant stops at the first failing assertion, so it does not independently exercise the test's second scenario. |
| **R5 — foreign cancellation downgrades absence history** | **Resolved.** `crates/store/src/ext_m03.rs:168–189` checks the event's origin and cancellation flag against stored facts and prevents replacement or clearing of an origin whose absence-history flag is true. Both own-enrollment (`:527`) and foreign-removal (`:1284`) transitions call it before updating the record. | `tests/integration/store_m03.rs:2154`, `foreign_removal_cancel_cannot_downgrade_absence_history`, and `:2248`, `enrollment_transition_cannot_downgrade_absence_history`, both pass. They check refusal without writes and an allowed transition preserving history. Restoring the parent's `ext_m03.rs` in scratch makes **both fail, each exit 101**. The foreign probe admits the forged cancellation back to `Planned` with the flag cleared; the own-enrollment probe admits a downgrade on another event. **The regressions detect the original defect and the shared history-preservation requirement.** |

**Pause and connection-policy ruling**

**The code complies with the established behavior.** `policy_reader` returns an empty set for pause and connection-policy actions (`narrowing.rs:967–970`), so these writes take the zero-gate transaction and do not invalidate an active grant's in-flight permit. Pause still prevents new activation. `SetLockBehavior(RevokeOnLock)` and earlier cutoffs use the full signing-narrowing protocol.

This matches spec §5.6 (`spec.md:246`), ADR-0006 §13.6 item 1, and M01's pause-free `continuing_policy` (`crates/app/src/operations.rs:905`). The new tests at `tests/model/narrowing_m03.rs:3199` and `:3237` pass: pause leaves existing signatures working while refusing a new activation, and stricter connection policy leaves signatures working. The existing M01 test `r137_3_a_narrowing_inside_the_approved_delta_and_a_pause_keep_the_grant` (`tests/model/revocation.rs:3581`) also passes, including continuing binding and issuance after pause. ADR-0008 D8 item 1 (`:2245`) governs effective connection policy separately.

**Documentation limit:** the supplied main file's §17.16, beginning at line 3615, contains five numbered R1–R5 rulings but no explicit pause/connection-policy follow-up. The code comment's “§17.16 follow-up” reference therefore cannot be verified from that section. The behavioral conclusion above is grounded in the spec, M01 ruling, D8, and executed tests.

**New defects**

None found in the changed production code. No additional severity-tagged finding or new-defect probe is warranted by the evidence collected.

**Commands and validation**

Run from the reviewed worktree; all three exited **0**:

```text
cargo test --locked -p heimdall-runtime --test model_narrowing_m03
    55 passed; 0 failed
cargo test --locked -p heimdall-testkit --test integration_store_m03
    27 passed; 0 failed
cargo test --locked -p heimdall-app --test model_revocation r137_3_a_narrowing_inside_the_approved_delta_and_a_pause_keep_the_grant
    1 passed; 0 failed; 52 filtered out
```

Seven isolated scratch mutation runs used `cargo test --locked -p heimdall-runtime --test model_narrowing_m03 <filter>` or `cargo test --locked -p heimdall-testkit --test integration_store_m03 <filter>`, with the seven test names listed above. **All seven compiled and exited 101 on their behavioral assertions/timeouts**, rather than failing to build. Each mutation was restored before the next mutation family.

Inspection included `git show 6c6b5e06`, `git diff 87b9a263 6c6b5e06`, caller searches with `rg`, and line-numbered source reads. A byte comparison against the fixed commit passed for all six reviewed files and all restored scratch inputs. `git status --short --untracked-files=no` produced no output, **exit 0**; the pre-existing untracked task notes were preserved. No tracked worktree file was edited. No commit, push, branch, stash, process termination, custom target directory, `cargo clean`, or validation wrapper was used.

**Changed files:** only this report is retained outside Cargo build outputs. Mutation sources were created under `/tmp/hm-w0-recheck`, using an archive of the fixed commit and a symlink to the existing worktree `target/`; temporary sources, scripts, and logs were removed afterward. The pre-existing Cargo cache was preserved. The required prototype-output size check found none of the three prototype output path classes in this worktree (`du` exit **1**); the production `target/` was approximately 41 GB before and 42 GB after the review runs.

Not checked: the full workspace suite, clippy, `tools/validation/check.sh`, or native Windows/WSL behavior.
Risk/limit: this verdict covers the five reported findings and touched code; the absent explicit §17.16 follow-up is a documentation discrepancy, and the R2 regression independently exercises only `automatic_activation` removal.
