merge

Scoped independent re-check of **M05-W2-R01**, at `27bef72a30c72567ddf035f08b9e13cc21ebe1c8` (`m05/w2`). The fix closes the reported in-flight delegation escape. No introduced finding or incomplete R01 path was established in this range. This is the wave's one scoped re-check under ADR-0009 §2.1, not another full review or a declaration that all merge-candidate platform gates are complete.

## Setup and scope

| Command | Exit | Observed result |
|---|---:|---|
| `git status --short` before checkout | 0 | Clean |
| `git fetch origin m05/w2` | 0 | Requested branch fetched |
| `git checkout --detach 27bef72a30c72567ddf035f08b9e13cc21ebe1c8` | 0 | Detached at requested merge |
| `git rev-parse HEAD` | 0 | `27bef72a30c72567ddf035f08b9e13cc21ebe1c8` |
| `git show -s --format='%H%n%P' HEAD` | 0 | First parent `28d54e3b96af12491c8f2b6b18832fd4b379c022`; second parent `518f5c798a750f11326f3ecd18c67287474aec05` |
| `rustc --version` | 0 | `rustc 1.99.1 (58cf8f9c3 2026-10-13)` |
| `uname -sm` | 0 | Darwin arm64 |
| `git diff --name-only 28d54e3b...518f5c79` | 0 | Identified the M03 import; excluded it from review |
| `git diff 28d54e3b 27bef72a -- <the eight requested paths>` | 0 | M05-only scope: eight paths, +261/−18 |

I read the archived W2 R01 section first after checkout, then ADR-0009, ADR-0011 §7, ADR-0008 D2, the requested M05 diff and the necessary connected activation/recovery/coalescing code. The active Codex-home and repository rules were also read. Read-only inspection used `rg`, `git diff`, `git ls-tree`, `sed`, `nl`, `cat` and `ls`. Unmatched exploratory searches/absent globs returned lookup errors; these were not test failures. The memory keyword lookup found no relevant Heimdall entry and supplied no review facts. No nested reviewer was started: this assignment itself is the independent scoped re-check.

## 1. R01 completeness

**verified** for the reproduced race and the additional in-process recovery/coalescing scenarios below; connected-path and termination conclusions are source inspection.

- `crates/app/src/operations/stop_m05.rs:205` walks the actual parent **binding**, checks that binding's environment/work stop, then follows `b.parent`. It does not use the shared grant's other consumers as a substitute for that lineage. A grandchild consequently checks its immediate parent's work and the earlier bindings in the same recorded delegation chain.
- `crates/app/src/operations.rs:2204` invokes this from `activation_refusal`, retaining the earlier grant-state, tombstone, own-work and all subsequent environment/policy/time/mechanism checks. A new-grant refusal uses `PreparationFailed`; it does not silently activate or turn into a successful attach.
- The preparation attempt (`operations.rs:7346`), recheck (`:7999`) and commit (`:8298`) derive the parent from the persisted delegate request through `parent_of`. Ordinary `ensure` requests have no parent. Restart recovery (`:5881`) loads open operations and drives the same pipeline (`:6204`) from durable requests and receipts, so it does not lose this parent after restart.
- Every later bind of an existing delegated binding supplies **that binding's** `b.parent` (`operations.rs:10043`). It cannot accidentally check only a different work ID on the same grant. Grant/ancestor tombstones and the binding's own state still apply independently.
- A coalesced follower skips preparation, but still reaches recheck and commit using its own stored request. Both coalesced leader orders were exercised: A's child refused and B's child remained bindable. Failed/stale leader attachment can fall back to a separate preparation without discarding B's parent identity.
- I-1's reuse probe (`stop_m05.rs:1409`) deliberately passes `None`, not a delegated parent. Its search first excludes `b.parent.is_some()` (`:1371`) and requires `g.parent.is_none()` (`:1379`); reuse itself is ensure-only. Thus the added parameter does not introduce an I-1 route around a delegation's parent check.
- Termination: a missing parent or absent next parent returns immediately; a cycle is bounded by `MAX_ANCESTRY = 64`. The helper returns `None` when the bound is exhausted or a parent row is absent; it does not claim such corruption is a newly detected stop. No ordinary writer in the inspected paths creates a binding cycle, and no binding-deletion path was found. Cycle/missing-row corruption was inspected, not dynamically injected.

The retained regression `tests/e2e/m05_stop.rs:808` passed in the requested eight-test suite. It holds a child before its effect, stops A while B shares the grant, then asserts `CREDENTIAL_EXPIRED / work_stopped`, no usable child grant, and an adapter `Revoke(child_grant)` cleanup event. Repeat stop and reconstruction preserve refusal; B binds successfully.

**Original review probe:** `w2.md` refers to `review-out/shared-stop-delegation-probe.rs`, an untracked artifact absent from this fresh checkout and absent from the archived review directory's tree listing. I could not rerun that missing file byte for byte. I reconstructed its documented real-concurrent A/B + paused delegated child scenario under the original test name `review_shared_work_stop_rejects_inflight_delegation`, now requiring refusal. Its source is retained in [shared-stop-delegation-probe.rs](shared-stop-delegation-probe.rs). It also confirms B can create and bind a new child after A stops. This is an explicitly reconstructed probe, not a claim to have recovered the original author's source.

Additional temporary tests in that artifact:

1. `review_recovery_checks_parent_before_recheck_and_commit`: two cases. Interrupt a child before recheck and before commit using the existing `ScriptedStageHook`, verify its operation is still running and grant preparing, stop A, then reconstruct `Operations`. Startup recovery fails the operation with `CREDENTIAL_EXPIRED`, leaves the child grant `Failed`, records credential revocation, and leaves B bindable. This exercises an **unfinished** child's startup recovery, beyond restarting an already-refused child.
2. `review_coalesced_children_preserve_b_in_both_leader_orders`: two cases. Make A/B children concurrent and hold the leader in preparation, then stop A. With either A or B as leader, A's child refuses with `work_stopped`; B's child succeeds and binds.

The refused new child grant becomes **Failed**, while the applied adapter credential is **revoked**. Those are distinct observations. The proofs use production `Operations` and SQLite with a fake adapter; they do not establish a remote SSH effect or native key destruction.

## 2. Over-blocking and unchanged unshared behavior

**verified** for the exercised scenarios. The baseline `stop_one_job_leaves_the_other` passed: B and unrelated C remain usable after A's stop, stopped A cannot reactivate, and stopping unshared C revokes its grant. The new regression additionally leaves B active through repeat stop/restart. The reconstructed probe successfully delegates through B after A stops, and the coalesced test preserves B's child in both leader orders.

Source inspection agrees: the check walks only the chosen parent binding's chain, uses each row's own environment/work ID, and does not equate stopping A with stopping their shared grant. An unshared ordinary ensure has no delegation parent, so its prior own-work and grant-revocation paths remain unchanged. The whole requested app suite passed as supporting regression coverage.

## 3. Signature ruling and Windows fixture changes

**Signature ruling — verified by diff/design inspection.** ADR-0011 §7.2 now explicitly permits a signature already admitted on the stopped work's shared reference to complete within its permit expiry, while refusing newly admitted signatures and retaining the shared ordinary-alias residual. This is the supplied orchestrator's settled ruling. The addition is documentation only; the scoped code change does not loosen signer gates, expiry, revocation tombstones or consent checks. I read ADR-0008 D2's permit/release bounds as design context; I did not reopen the M03 implementation review or execute a native wire-signature probe.

**Windows fixture changes — verified by source inspection; native Windows execution blocked by the missing Windows platform in this local review.**

- `crates/testkit/src/workspace.rs:69`: Unix still clears its environment, now retaining only PATH, temp variables and LANG. Windows preserves system variables needed by Git for Windows, but case-insensitively removes every inherited `GIT_*` variable before installing the scratch settings. Therefore inherited `GIT_CONFIG_*`, repository/worktree/index redirects and command-scope config injection do not survive that loop.
- On both branches, `HOME`, `USERPROFILE` and `XDG_CONFIG_HOME` point inside the fixture; `GIT_CONFIG_GLOBAL` names the fixture-created empty file and `GIT_CONFIG_NOSYSTEM=1` disables system configuration (`workspace.rs:98`). Fixed identity, disabled hooks/signing and noninteractive Git remain. The HOME/global/nosystem isolation requested in this re-check is retained; no owner Git configuration was used as test material.
- `tests/integration/portable.rs:352` changes only map-key representation: relative path components join with `/`, making the existing `.ssh/known_hosts` key comparisons apply on Windows too. Directory entries and exact file-byte values remain in the map; no comparison, table count, authority fingerprint or assertion is removed.
- `tests/model/idempotency.rs:605` changes only the platform-specific absolute fixture cwd. It retains the same model, concurrency, idempotency, context/digest conflict checks and coverage assertions. The observer is scripted, so this path is a valid context input, not an actual owner filesystem target.

The context journey with real scratch Git repositories, portable integration suite and idempotency model all passed locally. This does not execute the Windows-only environment branch or prove native Windows behavior.

## 4. Executed tests and own revert proof

All commands below actually ran. `python3 review-out/run.py <label> <command>` captured sanitized output, actual exit codes, elapsed time and test-result lines in [commands.jsonl](commands.jsonl). It set TMPDIR to the one review-owned `/tmp/hm-recheck-…` root, removed any inherited Cargo target override, and used this checkout's default `./target`. No `--target-dir`, `cargo clean`, `cargo run`, direct `heimdall` or direct `ssh` invocation was used.

| Executed command | Exit | Counts/result | Sanitized output |
|---|---:|---|---|
| `cargo test --locked -p heimdall-runtime --test e2e_stop_m05` | 0 | test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.15s | [stop.log](stop.log) |
| `cargo test --locked -p heimdall-runtime --test e2e_context_m05` | 0 | test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.67s | [context.log](context.log) |
| `cargo test --locked -p heimdall-runtime --test integration_portable` | 0 | test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.71s | [portable.log](portable.log) |
| `cargo test --locked -p heimdall-app --test model_idempotency` | 0 | test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 15.89s | [idempotency.log](idempotency.log) |
| `cargo test --locked -p heimdall-app` | 0 | 178 passed: 75 unit + integration groups 4, 16, 54, 29; 0 doc tests; 0 failures/ignored | [app.log](app.log) |
| `cargo test --locked -p heimdall-runtime --test e2e_stop_m05 review_` | 0 | test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.06s | [probe.log](probe.log) |
| `cargo test --locked -p heimdall-runtime --test e2e_stop_m05 review_coalesced` | 0 | test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 0.06s | [coalesced.log](coalesced.log) |
| `cargo test --locked -p heimdall-runtime --test e2e_stop_m05 shared_work_stop_fails_a_child_still_preparing` | 101 | test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.03s; error: test failed, to rerun pass `-p heimdall-runtime --test e2e_stop_m05` | [revert-parent-work.log](revert-parent-work.log) |
| `cargo test --locked -p heimdall-runtime --test e2e_stop_m05 shared_work_stop_fails_a_child_still_preparing` | 0 | test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.04s | [restore-parent-work.log](restore-parent-work.log) |

The five requested commands passed **208 test executions**, with zero failed or ignored tests. This includes the four idempotency tests twice, once alone and once within the 178-test app suite: **204 distinct baseline tests**. The three temporary probe tests added three passing executions (two of those each loop over two interleavings), and the restored regression added one passing execution. The only failure was the intentional revert run: **0 passed, 1 failed**, not a compile failure.

**Own revert proof:** I temporarily inserted `return Ok(None)` at the beginning of `parent_work_refusal`, after first removing all temporary probe additions from the test file. The unchanged retained regression then failed at `m05_stop.rs:879`: its expected-refusal assertion received a completed `Succeeded / AccessReady` child. I restored `stop_m05.rs` to its original bytes in a `finally` block and reran the same regression: **exit 0, 1 passed**. The disabled helper produced an unreachable-code warning, but compiled and reached the behavioral assertion. This independently confirms the causal fence described by the checked-in `revert-r01-inflight-child.json`.

[restoration.json](restoration.json) records byte comparisons and SHA-256 values:

| Temporarily changed tracked file | Original and restored SHA-256 | Byte identical |
|---|---|---|
| `tests/e2e/m05_stop.rs` | `0ddf3ac17b9b3be2250a59ba8de78087d0a8f622a10ef8db2e96bb6ffded7ee2` | true |
| `crates/app/src/operations/stop_m05.rs` | `82a53ff4cf9f05d5fce145e54030bfaafbb814d05931d85a9784cdbdcf26d301` | true |

Final `git diff --exit-code` and `git diff --cached --exit-code`: **exit 0 each**, no tracked changes. `git status --short`: **exit 0**, only `?? review-out/`.

## Findings

None. No `M05-W2-RC01` is raised. Within the specified M05 range, the evidence supports closing M05-W2-R01 under ADR-0009 §2.1.

## Limits, changed files and risks

- **Changed files:** only untracked report/DONE, runner, sanitized logs, reconstructed temporary-probe source, restoration metadata and original-byte backups under `review-out/`, plus normal build outputs under `target/`. No tracked implementation or test change remains; no commit, push or PR was made.
- **blocked:** native Windows/WSL verification is unavailable on this Darwin arm64 host. The Windows-only Git environment branch and Windows absolute-path behavior were inspected, not executed natively. No devbox run was requested/performed here. ADR-0009 merge-candidate native gates remain the orchestrator's responsibility; this verdict is the scoped code-review verdict.
- I did not run `tools/validation/check.sh`, the full workspace suite, real SSH/client/signer/secure-store/lock tests, or OS-kill crash recovery. The recovery probes reconstruct in-process `Operations` over the same real SQLite store; they are not native process-death evidence. Grandchild chain traversal and cycle/missing-row termination were source-inspected, not separately fault-injected.
- The original untracked reviewer-probe source is unavailable. The retained reconstruction reproduces its documented race and checks refusal/cleanup plus B's continued authority; it is not byte-identical provenance evidence.
- No owner's keys, agent, keychain, password manager or SSH configuration was a test target. The tests use disposable fixtures. Cargo output was sanitized before being emitted/retained by the runner.
- `du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist`: **exit 1**, no matching prototype build-output directories. `du -sh target`: **exit 0**, **4.5G** retained. No target or review-output deletion was performed, per the task packet; the orchestrator removes this worktree. The single review-owned temporary root was removed after the last test.

Risk to carry forward: native Windows and integration-wide gates remain outside this re-check. No additional scoped correction is required by the observed results.
