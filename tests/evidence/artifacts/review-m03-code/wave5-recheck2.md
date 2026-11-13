# Heimdall M03 wave 5, round 8 — independent re-check

**Verdict: fix first.** The original five scenarios now pass their regressions, and all five semantic reversions fail assertions. The fixes are not complete on every path: the stop-to-lock handoff can discard a replacement runtime's new CA record; publication has an unfenced re-reservation branch; cancellation can release an admission before its detached store write; and concurrent resumes duplicate deferred verification. ADR-0008 §17.31 item 8 is also unimplemented.

Reviewed the exact range `0cd94961..ccf23db5`, with detached HEAD `ccf23db5ffc2debb41c17180b1013378864b2dab`. Host: macOS arm64, Rust/Cargo 1.99.1. I read the production diff before the earlier re-check, ADR rulings and round notes. Notes were treated as claims. This re-check was performed independently, without further delegation.

All builds/tests ran in the requested detached worktree and its ordinary `target/`. Tests used disposable fixture keys, scratch homes, fixture agents, loopback servers and an isolated product-file keychain. The owner's keys, agent, SSH files, login keychain and real servers were not test targets. No implementation fix, commit, push, main-checkout edit or other-worktree edit was made.

Source locations below are relative to the repository and refer to the reviewed HEAD. `<scratch>` means `/tmp/hm-recheck2-m03w5`; `<repo>` means the source clone.

## 1. Is each earlier finding fixed on every path?

| Finding | Result | Evidence |
|---|---|---|
| W5-C01 | **blocked** by D01 below | Failed/dropped shutdown refuses before the purge read/delete; a held replacement lock refuses; startup between final read and deletion is excluded. The original scheduled-interleaving regression passes. A replacement that writes a new CA and releases its lock before the purge acquires it is missed by the final comparison. |
| W5-C02 | **blocked** by D02–D04 | All five checked-in fence e2e tests pass: pre-fence `StepResult` recording, deferred resume, verification reservation refusal, direct enrollment admission and direct issuer admission. Both paused reservation/acquisition model tests pass. Publication re-reservation and cancellation still escape the intended boundary; two resumes run verification twice. |
| W5-C03 | **verified** for the original scenarios and inspected finalization routes | Both original manual-recovery probes pass. `finish_removal` at `crates/app/src/operations/enrollment_m03/steps.rs:1724` performs residual clearing, transition and issuing-set update in one transaction. Normal removal, rollback, already-absent removal, reconcile-applied and manual-recovery absence use it. Foreign removal correctly does not mutate the own-CA issuing set. |
| W5-C04 | **verified** | These checks were already present at the base, from round 7. `payload_agrees` at `crates/store/src/ext_m03.rs:327` checks all hold-restating events against the stored hold kind. All three mismatch regressions pass, including unchanged enrollment/event documents after refusals. Recovery purpose remains unchecked under the explicit §17.31 item 7 decision; I do not reopen that accepted exception. |
| W5-C05 | **verified** for the original native scenario | The restore-then-retire product-file test passes on macOS. It verifies current-generation deletion, retired CA, preservation/listing of the denied old item, successful completion, manual Keychain Access guidance and no restore advice. Current and displaced items use distinct deletion handling. Reverting it reproduces exit 4, effect `none` and restore advice after retirement. |

The checked-in suites pass even though the additional probes below fail. Passing them therefore does not establish that all fence and purge paths are covered.

## 2. W5-C01: exclusion, writers, handoff, platforms and crashes

### Writer audit

I searched production Rust sources for store/SQLite opens and state-database accesses, traced callers, and separated test-only writers from executable paths.

| Writer or reader | Lock relationship |
|---|---|
| Runtime database open, migration, backup and initial recovery | The only production read-write `Store::open` call found is `crates/runtime/src/service.rs:498`, after `InstanceLock::try_acquire` at `:493`. Store migration/backup work occurs within that locked startup. |
| Application mutations, supervision, catalog/setup and time-anchor writes | Use the runtime-owned store. I found no separate production CLI read-write database open. This establishes the open-path audit, not cancellation safety; D03 demonstrates a detached application write that outlives its admission. |
| CLI database inspection | `crates/heimdall/src/{doctor_cmd.rs:492,m03_cmd.rs:365,issuer_cmd.rs:136,uninstall_cmd.rs:237}` and the latter's bundle/count helpers open read-only. They do not migrate. |
| Issuer child | `crates/issuer/src/child.rs:331` opens read-only. Native secret-store writes are separate from state-database writes. |
| CLI purge | `purge_locked` at `crates/heimdall/src/uninstall_cmd.rs:1770` acquires `service.lock` before its final database read and keeps it through deletion. The lock file is retained. |
| Direct fixture writes | Unit/model/e2e seeds and probes use disposable stores. They are not additional production executable writers. The replacement probes explicitly acquired the real instance lock before writing. |

**Observed:** a failed/dropped stop refuses without deleting; another holder causes a bounded refusal; a briefly held lock is waited for; startup under the purge lock fails before changing the database. A replacement's new foreign-removal obligation remains protected even if the replacement releases its lock before uninstall obtains it.

**Remaining handoff issue:** there is time between shutdown/fence release and the CLI taking `service.lock`. Exclusivity makes the later read/delete pair safe against a compliant *concurrent* writer, but does not identify all changes a replacement finished during that handoff. The final comparison ignores CAs and their locators. D01 demonstrates the resulting deletion.

**Lock wait:** `instance_lock` at `crates/heimdall/src/uninstall_cmd.rs:1798` retries nonblocking acquisition every 100 ms, with a 10 s configured wait. While the lock remains held it refuses without reading/deleting. On success it performs a fresh final read under the acquired lock. The polling boundary does not itself create an unlocked read/delete interval; the check can accept an available lock after a scheduling delay beyond the nominal deadline, but still holds exclusion while reading/deleting. I found no safety defect specific to that timeout boundary.

**Platforms, by code:** `crates/runtime/src/instance.rs:36` opens the same persistent `service.lock` with create enabled, truncation disabled, and uses standard `File::try_lock`: `flock` on Unix and `LockFileEx` on Windows. `WouldBlock` becomes `AlreadyRunning`; other errors refuse the purge. Neither runtime nor purge unlinks the lock file, avoiding a second-inode lock bypass. Windows execution is **blocked: native Windows host unavailable**. Linux/WSL execution is **blocked: native Linux/WSL hosts unavailable**. Their paths were read; no native claim is closed.

**Crash:** an added macOS child-process probe acquired `InstanceLock`, confirmed exclusion, killed only that exact test-owned child, and then successfully reacquired the lock while its file still existed (exit 0). The kernel releases the dead process's lock. This tests the actual lock type used by the CLI, not a complete uninstall crash at every instruction. A crash midway through the multi-file deletion can still leave partial cleanup; no deletion-atomicity or power-loss claim was tested.

## 3. W5-C02: shared admission boundary and deferred work

- The dispatcher and direct `enrollment_request`/`issuer_request` routes use the shared classification. Approval takes an admission; denial and permitted truth-recording/read-only requests remain available. `managed_reissue_pass` holds an admission for the pass. The supervisor wraps `reverify_pass`; that pass's effectful per-record work also enters `enrollment_request`.
- Grant and verification reserve functions retain a local guard across their awaited `write`. The two deterministic paused-reservation tests demonstrate acquisition waits on the normal completion path. **Cancellation is different:** `write` dispatches a `spawn_blocking` transaction. Dropping the outer future drops the guard while that transaction continues; see D03.
- Publication can call `reserve_entry` directly when the generation changed, bypassing both guarded reserve functions. See D02. The ordinary managed driver actually uses this publication/re-sign loop; this is not an unused API.
- I found no lock-order deadlock in the new mutex/counter/notification implementation. Admissions never wait; acquisition marks `acquiring`, refuses new work, and waits for the admitted count to reach zero. Nested work may be refused during acquisition, but does not wait while holding another admission. Reservation joins can prolong acquisition; the 20 s acquisition timeout fails closed. Nested-admission, acquisition-drain and cancelled-acquisition tests pass. This is source analysis plus targeted scheduling tests, not a starvation/soak proof.
- The pre-fence `StepResult` is committed before follow-through is attempted. The original probe confirms no new certificate under the held fence, and the stored `applied_unverified`/running operation remains available. The checked-in sequential resume test verifies that the next `enroll step` completes it after release. Reconcile has the equivalent retry path by inspection. No discarded step result was observed. **Exactly-once resume is false:** two concurrent steps sign four certificates and one reports `STATE_UNAVAILABLE`; D04 reproduced twice.
- The newly ruled treatment of a fence refusal inside verification is absent; D05 covers the required forced-refusal case.

## 4. New findings

### W5-D01 — medium — A replacement that already stopped can have its new CA silently purged

**Location:** `crates/heimdall/src/uninstall_cmd.rs:336`, `:1783`.

**Scenario:** after the confirmed stop, a replacement obtains the real instance lock, records a new active CA and its exact store locator, and stops/releases the lock. Uninstall then obtains the lock. `same_obligations` compares enrollments, foreign removals, operations and unresolved steps, but excludes CAs/locators. With no new remote obligation it accepts the old confirmation and deletes the new CA record too. The new item is absent from the confirmed retirement/inventory report.

**Probe:** `uninstall_cmd::tests::recheck2_purge_refuses_new_ca_from_replacement_that_already_stopped`, exit **101**, reproduced initially and again with a recorded locator. It confirmed the extra CA existed before calling the real `purge_now`/`purge_locked`; the helper returned `Purged(Ok(()))` and deleted the database. This schedules the store/lock/purge interleaving; it does not claim a naturally timed two-CLI reproduction or private-key deletion. The companion foreign-obligation probe exits **0**, confirming that comparison branch works.

**Suggested fix:** record the expected post-retirement CA/item inventory while the original fence is held, then compare the final locked inventory against it. Permit only this uninstall's known changes; refuse newly added/replaced CA records or locators. Preserve the lock through deletion.

This is a remaining handoff case in the C01 fix; the narrow comparator pre-existed round 8.

### W5-D02 — medium — Publication re-reserves under a held uninstall fence

**Location:** `crates/app/src/operations.rs:11770`, `:11871`; caller `crates/app/src/managed/driver.rs:318`.

**Scenario:** reserve a grant certificate, take the uninstall fence, then advance the authority generation without invalidating the grant. `publish_issuance` voids the old entry and directly calls `reserve_entry`, returning a fresh unsigned reservation while the fence is held. The managed driver can then sign that replacement.

**Probe:** `recheck2_publication_must_not_rereserve_under_held_fence`, exit **101**. A managed model fixture reserved under a verified CA, acquired the fence, advanced a policy revision, and published the old entry. Observed `Ok(Rereserved { ... state: Reserved ... })` and one fresh persisted reservation under the held fence. Signing of that replacement is source-derived, not independently exercised by this model probe.

**Suggested fix:** put the publication branch that can create a reservation under the same reservation admission, held through its store commit, including cancellation handling in D03. Audit both `reserve_entry` callers, rather than treating the initial reserve wrapper as the only creation point.

The branch pre-existed; round 8's claimed shared boundary misses it.

### W5-D03 — medium — Cancellation drops the admission before the detached store write ends

**Location:** `crates/app/src/operations.rs:5599`, `:11646`; verification counterpart `crates/app/src/operations/verification_m03.rs:240`; cancellation path `crates/ipc/src/session.rs:27`, `:724`.

**Scenario:** a reservation passes admission and queues its blocking transaction. The client disconnects or the dispatch future is otherwise dropped. The async stack's `FenceAdmission` is dropped, but an already started `spawn_blocking` transaction cannot be cancelled that way. Acquisition sees zero admissions and succeeds before that reservation commits.

**Probe:** `recheck2_cancelled_reservation_keeps_admission_until_store_write_finishes`, exit **101**. The existing store fault-hook interface paused the grant reservation at `BeforeTransaction`, before taking the store mutex. The test cancelled and awaited the reservation task, started acquisition, and observed acquisition complete before releasing the transaction. It then released/joined the work and verified the detached write had committed one issuance entry. All paused work was released before the failing assertion. No deleted obligation was claimed by this probe.

**Suggested fix:** retain the admission in the owner of the actual blocking transaction, or use a cancellation-safe task that owns the admission until the transaction finishes. Releasing the caller future must not decrement the last admission while its accepted write remains queued/running. Cover both reservation tables.

This invalidates the normal-path guard-lifetime argument added in round 8.

### W5-D04 — medium — Two resumes run the same deferred verification twice

**Location:** `crates/app/src/operations/enrollment_m03/steps.rs:582`, `:1080`, `:1188`; `crates/app/src/operations/enrollment_m03/verify.rs:70`.

**Scenario:** after an append result was durably deferred under the fence, release the fence and submit two concurrent `enroll step` requests for its operation. Both observe work to verify. `start_initial_verification` returns success even when another caller already moved the record to `verifying`; each then calls `verify_operation`. There is no shared per-operation driver exclusion around these calls. Reconcile uses the same unclaimed start/verify sequence.

**Probe:** `fence::recheck2_deferred_verification_is_not_duplicated_by_two_steps`, exit **101**, twice. It reused the original append-under-fence fixture, lifted the fence, and ran `tokio::join!(w.step(&op), w.step(&op))`. Both runs signed **4** certificates rather than the expected **2**; one request succeeded and one returned `STATE_UNAVAILABLE`. The assertion was on the certificate count, not compilation or a timeout.

**Suggested fix:** serialize initial verification by operation across step, reconcile and immediate follow-through, using the existing single-flight pattern or an equivalent atomic claim. Followers should observe the same outcome instead of starting another verifier.

The new durable deferral exposes an existing lack of verification-driver exclusion; this is not evidence that all duplicate-driver behavior originated in this commit.

### W5-D05 — low — §17.31 item 8's fence-refusal handling and regression are missing

**Location:** `crates/app/src/operations/enrollment_m03/verify.rs:97`.

**Scenario:** `run_verification` returns `SERVICE_UNAVAILABLE / uninstall_in_progress`. `verify_operation` propagates only `InternalError`; every other error becomes a default inconclusive observation, which is recorded. The explicit new ruling requires returning the fence error without treating it as remote evidence.

**Probe:** `fence::recheck2_fence_refusal_is_not_recorded_as_verification_result`, exit **101**. A temporary debug-only forwarding method exposed the private start/verify sequence without changing its implementation. Under a held fence, the real reservation refused; the driver nevertheless returned `Ok(())`, signed nothing, and left the record `applied_unverified` after recording the inconclusive outcome.

**Suggested fix:** return the fence refusal before constructing/recording an `Observed`, and add the specified forced-refusal regression with before/after enrollment evidence and state assertions.

This is a missing explicit round-8 requirement. No ordinary IPC route that bypasses all outer admissions into this forced case was established; its severity reflects that limit.

## 5. Regression sensitivity

Five isolated semantic reversions were applied only in the disposable worktree, restoring each file in `finally`. Every case compiled, selected nonzero tests, and failed runtime assertions with Cargo exit **101**; none was credited for a compilation failure.

| Finding | Reverted behavior | Observed assertion failure |
|---|---|---|
| C01 | Drop the real instance lock before the scheduled final-read/deletion pause | Original scheduled-interleaving probe can obtain the supposedly excluded replacement lock. |
| C02 | Exempt verification reservation from the fence | Original direct reservation probe receives a successful persisted reservation. |
| C03 | Route manual-recovery absence directly to `move_ctx` again | Both original probes fail: residual retained and last issuing CA retained. |
| C04 | Remove the three additional hold-event arms, retaining `OwnerReverify` | All three mismatch regressions accept a mismatched event and fail. |
| C05 | Use the exact current-item deletion/refusal path on a displaced item | Native restore-then-retire returns 4, effect `none`, and restore advice. |

The four temporary probe files and every mutation were then restored byte-for-byte from HEAD. `git diff --exit-code` and `git status --porcelain` returned 0/empty. The restored HEAD then passed 173 binary unit tests, 88 enrollment e2e tests and 64 CLI e2e tests. The three ignored CLI entries are child-mode launcher tests invoked by their parent tests. Workspace/all-targets Clippy had already passed on the unmodified HEAD, as had 36 store integration tests and 21 store unit tests.

## Commands and real exit codes

Every Cargo invocation used the detached worktree. The command runner captured real subprocess status and sanitized output before saving/emitting it. **101** in the probe/mutation rows is Cargo's failed-test exit, not the product CLI's exit. Added `recheck2_*` probes were temporary and are described above; they were removed after execution.

| Command / context | Exit | Observed result |
|---|---:|---|
| `git -C <repo> worktree add --detach <scratch>/wt ccf23db5` | 0 | Requested detached worktree created. |
| `git log --oneline 0cd94961..ccf23db5`; `git diff --stat 0cd94961 ccf23db5`; production diff/caller reads | 0 | Single reviewed commit, 30 changed files; production diff read before notes. |
| `cargo test -p heimdall --bins --locked` [baseline-bins] | 0 | 173 passed. |
| `cargo test -p heimdall --test model_operations_m03 fence_ --locked` [baseline-model] | 101 | Requested package has no such test target; corrected in next model invocation. |
| `cargo test -p heimdall --test e2e_enroll_m03 fence:: --locked` [baseline-fence] | 0 | 5 passed, including the original three probes and direct issuer admission. |
| `cargo test -p heimdall-store -p heimdall-testkit --test integration_store_m03 --locked` [baseline-store] | 0 | 36 store integration tests passed. |
| `cargo test -p heimdall-runtime --test model_operations_m03 fence_ --locked` [baseline-model-corrected] | 0 | 2 reservation/acquisition tests passed. |
| `cargo test -p heimdall --test e2e_enroll_m03 recheck_manual_ --locked` [baseline-recoveries] | 0 | Both original manual-recovery probes passed. |
| `cargo test -p heimdall --test e2e_cli_m03 issuer::recheck_ --locked` [baseline-retirement] | 0 | Native restore-then-retire regression passed. |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` [baseline-clippy] | 0 | Workspace/all-targets Clippy passed on unmodified HEAD. |
| `cargo test -p heimdall-store --locked` [baseline-store-lib] | 0 | 21 unit tests passed; 0 doc tests. |
| `cargo test -p heimdall-runtime --test model_operations_m03 recheck2_publication_must_not_rereserve_under_held_fence --locked -- --exact` [probe-publication] | 101 | D02: fresh reservation created under held fence. |
| `cargo test -p heimdall --test e2e_enroll_m03 fence::recheck2_deferred_verification_is_not_duplicated_by_two_steps --locked -- --exact` [probe-two-steps] | 101 | D04: 4 signatures; one request reported STATE_UNAVAILABLE. |
| `cargo test -p heimdall --bins recheck_purge_must_exclude_writer_after_final_read --locked` [mutation-C01] | 101 | Reverted lock lifetime: scheduled-interleaving assertion failed. |
| `cargo test -p heimdall --test e2e_enroll_m03 fence::recheck_verification_reservation_refused_under_uninstall_fence --locked -- --exact` [mutation-C02] | 101 | Reverted verification admission: successful reservation violated refusal assertion. |
| `cargo test -p heimdall --test e2e_enroll_m03 recheck_manual_ --locked` [mutation-C03] | 101 | Reverted manual finalization: both original assertions failed. |
| `cargo test -p heimdall-testkit --test integration_store_m03 hold_that_differs_from_the_stored_record --locked` [mutation-C04] | 101 | Reverted extra hold checks: all three assertions failed. |
| `cargo test -p heimdall --test e2e_cli_m03 issuer::recheck_retire_after_new_item_restore_deletes_only_current_generation --locked -- --exact` [mutation-C05] | 101 | Reverted displaced-item handling: product CLI returned 4, effect none. |
| `cargo test -p heimdall-runtime --test model_operations_m03 recheck2_cancelled_reservation_keeps_admission_until_store_write_finishes --locked -- --exact` [probe-cancelled-reservation] | 101 | D03: acquisition completed before detached write; write later committed. |
| `cargo test -p heimdall --test e2e_enroll_m03 fence::recheck2_fence_refusal_is_not_recorded_as_verification_result --locked -- --exact` [probe-refusal] | 101 | D05: forced fence refusal swallowed as Ok/inconclusive. |
| `cargo test -p heimdall --bins uninstall_cmd::tests::recheck2_cli_crash_releases_instance_lock --locked -- --exact` [probe-crash-lock] | 0 | Exact test-owned child killed; lock successfully reacquired. |
| `cargo test -p heimdall --bins uninstall_cmd::tests::recheck2_purge_refuses_new_ca_from_replacement_that_already_stopped --locked -- --exact` [probe-replacement-stopped] | 101 | D01: new CA committed in handoff was purged. |
| `cargo test -p heimdall --test e2e_enroll_m03 fence::recheck2_deferred_verification_is_not_duplicated_by_two_steps --locked -- --exact` [probe-two-steps-repeat] | 101 | D04 reproduced: again 4 signatures and one STATE_UNAVAILABLE. |
| `cargo test -p heimdall --bins uninstall_cmd::tests::recheck2_purge_refuses_new_ca_from_replacement_that_already_stopped --locked -- --exact` [probe-replacement-locator] | 101 | D01 reproduced with exact store locator recorded. |
| `cargo test -p heimdall --bins uninstall_cmd::tests::recheck2_purge_refuses_obligation_from_replacement_that_already_stopped --locked -- --exact` [probe-replacement-obligation] | 0 | A replacement's new foreign obligation is caught after its lock release. |
| `cargo test -p heimdall-app -p heimdall-runtime --lib uninstall_fence --locked` [baseline-app-runtime-fences] | 0 | 4 app + 3 runtime fence tests passed (temporary forwarding method present, production logic unchanged). |
| `python3 (platform.system/machine; rustc --version; cargo --version)` [versions] | 0 | Darwin arm64; rustc/Cargo 1.99.1. |
| `du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist` [prototype-hygiene] | 1 | No matching prototype output directories; du reported missing patterns. |
| `du -sh target` [target-size] | 0 | Worktree target measured 10 GiB. |
| `cargo test -p heimdall --bins --locked` [final-bins] | 0 | Restored HEAD: 173 passed. |
| `cargo test -p heimdall --test e2e_enroll_m03 --test e2e_cli_m03 --locked` [final-e2e] | 0 | Restored HEAD: 64 CLI passed, 3 child launchers ignored; 88 enrollment passed. |
| `python3 <scratch>/mutate.py` | 0 | Five sequential semantic reversions each produced the required assertion failure; source restored individually. |
| Python restore of the four probe files from `git show HEAD:<path>` | 0 | Temporary source restored byte-for-byte. |
| `git diff --exit-code`; `git status --porcelain`; `git rev-parse HEAD` | 0 | Clean detached source, exact review head confirmed. |
| Python scratch process/keychain inspection (selected executable/PID fields only) | 0 | After suites finished, no executable under the scratch prefix; zero runtime keychain files. |

Read-only navigation used `git log/diff/show`, `rg`, `cat`, `sed` and Python source/caller inspections. Successful navigation groups exited 0. Exploratory searches referencing nonexistent `tests/e2e/enroll_m03/fx.rs` and an exploratory combined search ending at that path exited 2; other missing-path diagnostics in combined commands were followed by successful reads and those groups exited 0. These were not validation passes. No shell command's expected output was substituted for an observed result.

## Limits, changed files and cleanup

- **blocked:** native Windows, Linux and WSL execution, because those hosts were unavailable to this review. No cross-build/emulation was credited as native evidence.
- No full workspace test run, release-build gate, physical desktop-lock check, power-loss campaign, full uninstall crash matrix, naturally timed full-CLI restart race or concurrency soak was performed. Workspace Clippy covered all targets; the selected native suites supplied behavioral evidence.
- D01 is a scheduled real store/lock/purge-helper interleaving. D02 is a model with actual application/store code. D03 uses the existing fault-hook boundary to schedule a real detached blocking write. D04 uses actual loopback enrollment and the fixture issuer/verifier. D05 deliberately exposes a private driver through a temporary forwarding method. These differences limit the conclusions as stated per finding.
- No canary occurrence was found in captured validation output. No secret/private-key output was intentionally emitted. Runtime product-file stores lived inside scratch homes; fixture teardown left no runtime keychain file under the scratch tree. Only test-owned children were stopped, by exact child handles.
- **Persistent changed file:** this external report only. Temporary probe files: `crates/app/src/operations/enrollment_m03/verify.rs`, `crates/heimdall/src/uninstall_cmd.rs`, `tests/e2e/enroll_m03/fence.rs`, `tests/model/operations_m03.rs`. Semantic reversions additionally touched the reviewed verification-reservation, removal-finalization, store-payload and retirement files; each was restored immediately. No repository evidence record or implementation patch was left.
- Prototype-output hygiene command exited 1 because none of the three glob families existed. The worktree's own `target/` measured 10 GiB before cleanup; it is removed with the worktree.

**Cleanup confirmed.** The requested `git -C <repo> worktree remove --force /tmp/hm-recheck2-m03w5/wt` completed with exit **0**, removing the detached worktree and its complete build output. Exact-path Python removal of `/tmp/hm-recheck2-m03w5` then completed with exit **0**. Assertions confirmed the scratch root is absent, the worktree registration is gone, and this external report remains. Immediately before removal, the reviewed worktree was clean and there were zero scratch executables and zero runtime keychain files. The main checkout was clean at the final read-only status check. No pre-existing process was stopped.

| Cleanup command | Exit | Observed result |
|---|---:|---|
| Python pre-cleanup source/process/keychain assertions | 0 | Reviewed source clean; zero scratch executables and runtime keychain files. |
| `git -C <repo> worktree remove --force /tmp/hm-recheck2-m03w5/wt` | 0 | Detached worktree and entire target removed. |
| Python exact-path scratch removal and worktree/report/status assertions | 0 | Scratch absent; unregistered; report retained; main checkout clean. |

Not checked: native Windows/Linux/WSL, the full workspace test suite, release gates and the full uninstall crash/power-loss matrix.
Risk: merge would retain the demonstrated purge handoff, reservation-boundary and duplicate-verification defects; fix first.
