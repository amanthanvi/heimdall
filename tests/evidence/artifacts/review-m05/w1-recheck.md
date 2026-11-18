merge

Scoped independent re-check of M05-W1-R01 on `m05/w1`, range `22dfb168..e49f90d0`. No new full-wave review and no nested reviewer. **R01 is fixed correctly; no weakening or new defect requiring correction was found in this range.** This verdict addresses the requested fix round; it does not certify separate merge-candidate platform gates.

## Setup and scope

| Executed command | Exit | Observed result |
|---|---:|---|
| `git fetch origin m05/w1` | 0 | Requested branch fetched |
| `git checkout --detach e49f90d09e4ee919bc4440bd517d1c09621399de` | 0 | Detached at requested commit |
| `git rev-parse HEAD` | 0 | `e49f90d09e4ee919bc4440bd517d1c09621399de` |
| `rustc --version` | 0 | `rustc 1.99.1 (58cf8f9c3 2026-10-13)` |
| `uname -sm` | 0 | `Darwin arm64` |

Read the archived original review's R01 section first, then the working rules, ADR-0009 §2.1 and ADR-0011 I5, §2.3 and §10. Inspected all eight changed files and traced the connected authority paths with `git diff`, `rg`, `sed` and numbered source reads. One exploratory read of a nonexistent `crates/testkit/src/properties.rs` returned exit 1; the actual property configuration was located in `tests/model/trust_policy.rs` and read. This was an inspection typo, not a validation failure.

## 1. Correctness — verified

- [crates/app/src/operations/trust_m05.rs:1423](crates/app/src/operations/trust_m05.rs:1423) compares both optional common-directory identities. `None/None` matches; `Some/Some` uses `same_file`; appearance and disappearance both fail. Root path, root identity, digest, environment, profile-snapshot and managed-environment checks remain in place.
- [crates/domain/src/projection.rs:159](crates/domain/src/projection.rs:159) defines `same_file` as exact `FileIdentity` equality. Unix device, inode and optional birth time all count, including birth-time presence; Windows volume and 128-bit file ID count. This is the same equality used by linked-worktree membership and reconcile. It introduces no wildcard or path-based substitute.
- [crates/app/src/operations.rs:11340](crates/app/src/operations.rs:11340) routes every trust/reconcile approval through `precheck` before decision completion. A common-identity mismatch returns `DECISION_STALE` before completion, leaving the decision pending. The regression checks both the pending state and an unchanged state snapshot.
- [crates/app/src/operations/trust_m05.rs:1734](crates/app/src/operations/trust_m05.rs:1734) loads the stored trust basis; the new `WorkspaceRecord` receives its `git_common_identity` directly at line 1756. No approval-time observation supplies a replacement.
- Alternate paths were inspected: `build_trust` returning an existing trusted/member policy performs no workspace write; repeated requests reuse only the same kind/action/basis at the same generation, otherwise superseding the old decision (`pending_workspace_record`, line 1088). Re-approving a completed decision is refused by `Operations::decide`. Reconcile checks optional common identity with the same equality and constructs its new record from its recorded basis (lines 1503 and 1840). `extend_scope` and its coalescing paths update policy scope/decision bookkeeping, not workspace identity. The two production workspace constructors are trust and reconcile; the store's state-update method changes state only. No other path creating or updating common identity from a later observation was found.

## 2. R01 regressions and independent revert proof — verified

Every Cargo command below ran through `python3 review-out/run-check.py <label> ...`, which recorded the real Cargo exit, test-result lines and sanitized output in matching `.json` and `.log` files. All builds used this checkout's own `./target`, with no target override.

| Executed Cargo command / source state | Exit | Observed counts |
|---|---:|---|
| `cargo test --locked -p heimdall-runtime --test model_trust_policy` — exact requested commit | 0 | 8 passed, 0 failed, 0 ignored, 0 filtered |
| `cargo test --locked -p heimdall-runtime --test model_trust_policy trust_approval_refuses_a_changed_observation_without_consuming` — common comparison temporarily always true | 101 | 0 passed, 1 failed, 0 ignored, 7 filtered |
| Same filtered command — source restored byte for byte | 0 | 1 passed, 0 failed, 0 ignored, 7 filtered |

The temporary mutation replaced only `check_trust`'s `same_common` match expression with `true`; all other checks and the fixed persistence remained active. The reverted regression **compiled and failed an assertion**, at `tests/model/trust_policy.rs:912`, because the changed common directory was approved and `unwrap_err()` received success. This independently establishes that the new comparison prevents the reported consent bypass, even when persistence still uses the recorded basis. The restored test covers common-only replacement, disappearance and appearance, in addition to its original root/digest mutations, and checks stored identity after a successful unchanged approval.

Restored source was compared both with the backup and `git show HEAD:crates/app/src/operations/trust_m05.rs`. Original and restored SHA-256: `112a00d2543290a73e9efcbd2d35fcdb410ea6018292b2a429482d7f9ad17e68`. Evidence: `trust-baseline.json`, `trust-reverted.json`, `trust-restored-regression.json`, their sanitized logs, and `revert-source.json` under this report's directory. The commit's supplied revert-proof JSON was read as historical evidence; the exits above are from this re-check.

## 3. Test weakening / Windows fixtures — verified by source review and local model run

| Executed command | Exit | Observed counts |
|---|---:|---|
| `cargo test --locked -p heimdall-project --test model_project_pure` | 0 | 40 passed, 0 failed, 0 ignored, 0 filtered |

No existing assertion, oracle outcome or generator alternative was removed or relaxed. On Unix, fixture path and pointer-text transformations are identity transformations. On Windows, fixture keys/canonical observations use verbatim drive paths, callers supply absolute drive-qualified paths, and absolute Git pointer text gains a drive prefix. Relative pointers, `..` escapes, stale/absent/wrong backlinks, copied worktrees, malformed bytes, size bounds, identity absence, and manifest authority refusal remain covered. The P11 truth oracle and all pointer/backlink generator alternatives are unchanged; no hostile-path filter was added. The new path-form test is Windows-only; existing tests were not moved behind that platform condition.

P9 retains its configured 128 traces and all previous step alternatives. It adds common-only replacement/removal and `BadCwd` steps. The new step's early skips only omit requests for a missing directory or a reconcile with no workspace; they do not skip an existing approval/mutation branch or perform a state mutation. Its exercised requests require `USAGE_ERROR`, no decision reference, and unchanged pending records, workspaces and policies; the existing I1 check then runs. The fixed hostile-manifest/unattended-trust trace is added rather than replacing the property. `Seen.git` uses exact optional equality, so `None` does not match `Some`.

**Evidence qualification:** the task's claim that P9's oracle checks the *stored* common identity is imprecise. [tests/model/trust_policy.rs:1225](tests/model/trust_policy.rs:1225) captures the probe identity, and lines 1528–1533 / 1895–1900 compare approval-time observation with that captured value. P9's `check_i1` does not compare the new workspace record's common identity. The fixed regression at lines 921–925 and the existing trust test at line 807 do check stored common identity. This is not a weakened assertion or an incomplete R01 fix; the persistence check exists in the focused tests, and production persistence is directly from the recorded basis.

## 4. Crate regressions — verified

| Executed command | Exit | Observed counts |
|---|---:|---|
| `cargo test --locked -p heimdall-app` | 0 | 175 passed, 0 failed, 0 ignored; 0 doc tests |
| `cargo test --locked -p heimdall-project` | 0 | 40 passed, 0 failed, 0 ignored |

App breakdown: 73 library tests, 3 idempotency, 16 lock-behavior, 54 revocation, 29 signing-gates. Project's 40-test model is included again by its crate command; these are repeated executions, not 80 distinct tests. Structured results and sanitized logs are `app.json/.log`, `project.json/.log`, and `project-model.json/.log`.

## Findings

None. No `M05-W1-RC01` finding is raised. R01's consent bypass is closed, and no introduced issue meeting ADR-0009 §2.1's blocking conditions was found.

## Changed files, final state and limits

Retained changes are untracked review artifacts only: this report, `DONE`, the check runner, six pairs of command results/logs, the original-source backup, the restoration-hash record and final-state record, all in `review-out/`. No tracked implementation, test, plan or evidence changes remain. No commit, push, PR or direct `heimdall` invocation was made; no owner SSH files, agent or keychain were test targets.

Final checks: `git diff --exit-code` **0**, `git diff --cached --exit-code` **0**, `git diff --check` **0**; `git status --short --untracked-files=normal` **0**, showing only `?? review-out/`. HEAD is still the exact requested SHA. `final-state.json` records these source-state checks. Build-output inventory found no matches for the prototype target/node_modules/dist globs; `du -sh target review-out` exited **0** and showed approximately **4.0 GB** of build output. Nothing was deleted, as requested; the orchestrator owns worktree cleanup.

Not checked: native Windows/WSL execution and a fresh devbox run are **blocked for this re-check's independent evidence by the unavailable native environments in this checkout**; the Windows-only path test did not run on Darwin. The archived Windows summary is not a live re-run of this SHA. The full workspace gate and `tools/validation/check.sh` were not run for this scoped re-check. No native observer, secure-store or later-wave integration claim is closed by these model tests.

Risk: no remaining R01 risk was found in the inspected authority core. Native merge-candidate validation and later observer integration remain the orchestrator's separate gates.
