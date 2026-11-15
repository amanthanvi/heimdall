# Heimdall M03 wave 5, rounds 9–10 — independent re-check

**Verdict: fix first.** The original W5-D01–D05 probes pass, and eight semantic reversions fail their intended runtime assertions. The broader guarantees remain incomplete: a retry allowance can discard a new remote obligation; cancelled real issuer requests can execute after acquisition; holder scope is lost on verification and retained after release on retry; the sweep can follow a replaced ancestor; and it omits a cleanup-owned mux socket.

Reviewed `ccf23db5ffc2debb41c17180b1013378864b2dab..142fe3fa6a1d8d97828f6f4e19344e7252c5e065`, the two requested rounds, in a detached worktree at the latter commit. Host verified as Darwin arm64, rustc/Cargo 1.99.1. Production diff inspection preceded the archived reviews, ADR-0008 §17.31–§17.32 and round notes. Claims in those documents were checked against code and execution. No further delegation was used.

All builds used the detached worktree's ordinary `target/`. No build-target override, `cargo clean`, commit, push, main-checkout edit or other-worktree edit was made. Temporary probe/mutation edits were confined to the detached worktree and restored from its pinned HEAD. Disposable keys, scratch homes/stores and loopback fixtures were the only test material. The real-child probes ran the actual `heimdall internal issuer` executable with a disposable scratch secret store; they do not claim native product-keychain coverage.

All source locations below are repository-relative and refer to the pinned HEAD. `101` is Cargo's test/build failure, not a product CLI exit. Navigation commands are distinguished from validation. Status terms apply only to the stated scope.

## 1. W5-D01–D05: original probes and every-path assessment

| Finding | Original scenario | Broader assessment |
|---|---|---|
| D01, recovery inventory | **verified**: `recheck2_purge_refuses_new_ca_from_replacement_that_already_stopped` passes, as do the new issuer/locator, pending-registration, final-enrollment, issuing-set and journal comparisons in the binary suite. | **blocked** for the complete purge guarantee by E01. A retried remote record has a partial comparison despite being present in `RecoverySnapshot`. E04 and E06 affect the purge itself. |
| D02, publication re-reservation | **verified**: `recheck2_publication_must_not_rereserve_under_held_fence` refuses without changing the old entry; its unfenced control re-reserves. | Both `reserve_entry` call sites, at `crates/app/src/operations.rs:11756` and `:11912`, pass through admitted writes. Verification reservation is separately admitted. No additional reservation-creation bypass was found. E02 concerns execution of a previously issued child request. |
| D03, cancelled store write | **verified**: grant and verification cancellation regressions pass. Generic admitted-write cancellation also passes. | The blocking closure owns the reservation admission and current-task extension until `store.transaction` returns. This closes the demonstrated detached-write defect. **blocked** for the stronger lifetime-of-all-work claim by E02 and E05. |
| D04, duplicate verification | **verified**: two steps, step plus reconcile, concurrent re-verification resumes, cancelled leader/pending write and stale result-write regressions pass. | All production verification callers inspected converge on `verify_operation`; `verify_once` is private. The spawned leader retains the flight through its CAS result write. E03 is a newly introduced holder-scope failure on that path. |
| D05, fence refusal as evidence | **verified**: `verification_fence_refusal_is_returned_and_changes_no_evidence` and `refused_reverification_is_resumed_once_after_the_fence_lifts` pass. | The refusal is returned before result recording. The supervisor's verdict-less open operation resumes after release, and a later pass does not reserve another pair. |

The full baseline passed 190 binary tests, 98 enrollment tests, 16 managed tests, 62 runtime unit tests, 44 M03 operation-model tests, 22 issuer-operation integration tests, 21 store unit tests, 22 issuer unit tests and 36 issuer-child integration tests. Restored-source checks additionally passed 14 fence e2e tests and 5 application fence tests. These passes coexist with the new failures below.

## 2. Fence, admission ownership, cancellation and liveness

`write_admitted` at `crates/app/src/operations.rs:5613` moves ownership into `spawn_blocking`; cancelling its awaiting future cannot drop those owners early. `UninstallFence::write_extension` at `crates/app/src/operations/uninstall_fence_m03.rs:189` adds a counted owner for writes from the task holding an admission.

By inspection, task identity is accounting, not authorization: moving an admission retains its original task ID for removal, and dropping the last original owner removes that map entry. I found no evidence that an ordinary later task can inherit that entry through ID reuse. Child tasks do not inherit task-local holder scope or per-task membership automatically. The implementation explicitly moves an extension into the verification leader and takes a fresh work admission in an ensure's spawned pipeline. The production IPC session runs concurrent request futures on the connection task; its shared task count can conservatively extend another write on that task, which can delay acquisition but does not prematurely release an admitted transaction. This is source analysis plus cancellation regressions, not an exhaustive scheduler proof.

The child protocol is a separate ownership boundary: cancelling a request future does not retract the frame already delivered to the child. E02 demonstrates that its guard can disappear while the child still owes a load or signature. Holder work is another exception to the counter; E05 demonstrates that its exemption outlives actual ownership.

I found no permanent lock-order deadlock in the counter/mutex/notification design. Acquisition registers its notification before inspecting state, marks `acquiring`, refuses new work, and waits for admissions to drain. Admissions themselves do not wait, so nested admissions cannot form an acquisition/admission wait cycle. The supervisor does not synchronously wait for acquisition while holding a required store transaction. Reservations may join during acquisition; repeated joins can prolong it, but the 20-second `ACQUIRE_WAIT` returns a refusal rather than taking the fence early. Drain, nested admission, cancelled acquisition and cancelled-write tests pass. No fairness or sustained-load starvation proof was performed.

Acquisition is not a stop-all-writes boundary by design. Pre-dispatched remote-step results, denials, local cleanup and ordinary narrowing work may still update local state. Previously issued client-executed remote steps may still be outstanding; their unresolved obligations must cause the inventory check to refuse deletion. A7's time-anchor write remains an explicitly accepted exclusion: it is monotonic local time evidence. None of those exceptions establishes permission for the new CA/signing or stale-holder effects in E02/E05.

## 3. Purge, snapshot, links and retry semantics

The ordinary comparison is substantially stronger: `RecoverySnapshot::read` at `crates/heimdall/src/uninstall_cmd.rs:260` reads all classified row tables, selected meta keys, whole open/unresolved enrollment operations with journal digests and outstanding tokens, pending registration decisions, and projection-absence facts. Classification tests cover the current table, operation-kind, decision-kind and meta-key inventories. CA retirement allowances compare observed before/after records rather than merely accepting any retirement.

The final inventory/bundle read and deletion remain under `InstanceLock`, acquired after confirmed shutdown. The production read-write database-open route found is runtime startup, after that same lock. CLI and issuer-child opens are read-only. This excludes a compliant runtime between final read and deletion; it does not exclude filesystem directory replacement, as E04 shows. A replacement that writes and stops before lock acquisition is now caught for the ordinary recovery rows, but E01 bypasses that protection for part of a retried remote record.

The sweep removes ordinary files and binding sockets below the two intended leaf directories. The checked-in linked-`managed` refusal passes. An added nested-link control also passes: links inside both trees are removed without touching their external fixture target. Replacing the runtime-directory ancestor at the final-read/deletion pause instead causes outside deletion (E04). A stable mux socket belongs to the cleanup path but lies outside both swept trees (E06).

**Windows, by reading:** the purge uses the same `symlink_metadata`/`remove_dir_all` code, without an anchored directory handle or Windows-specific ancestor/reparse validation. The instance lock uses standard `File::try_lock` (`LockFileEx` on Windows), and is retained through deletion; it is not unlinked. No native Windows junction, sharing-mode, lock or secure-store claim is closed by this review. Linux/WSL execution is likewise blocked by unavailable native hosts.

The normal retry route is holder-only at entry, invokes the existing ordinary retry round with the configured cap, and does not call a re-arm/reset operation. The dispatcher holder-only test and the ordinary-round model test pass, including capped/stopped records: no count reset, lifted stop or extra adapter call. However, ownership is checked only before the loop; E05 shows that a formerly authorized retry can continue as a non-holder. No independent re-arm defect was found.

## 4. Previously unchecked areas

### Ensure and re-issue of the same grant

No duplicate same-grant issuance was observed in the tested interleavings. A first exploratory probe incorrectly assumed a fresh `ensure` would reuse the degraded grant; it failed that assumption because ensure returned a different grant. Corrected probes then passed:

- `recheck3_ensure_and_pass_do_not_duplicate_same_grant`: paused old-grant re-issue plus a new request for the same work; ensure created a distinct grant and the old grant had exactly one continuing certificate per pair.
- `recheck3_two_reissue_passes_do_not_duplicate_same_grant`: overlapping passes produced one re-issue per pair.
- `fence::recheck3_production_effects_exclude_second_same_grant_reissue`: repeated with the production managed adapter/effects/signer table after a simulated runtime restart, while the first pass was paused before signing. The second pass returned no repaired grant; the first repaired the original; ensure created a distinct grant. Total additional grant signatures were two for the one-pair setup: one old-grant re-issue and one new-grant activation.

The supporting boundary is `ManagedEffectsImpl::generate_key` (`crates/adapters/src/managed/effects.rs:517`) and atomic `SignerTable::register` (`crates/credential/src/table.rs:447`): a different effect token cannot register a second live key for that grant. Existing request replay also returns its recorded result rather than issuing again. This is targeted evidence, not a claim of a shared per-grant single-flight mechanism or exhaustive concurrent-failure coverage.

### Actual internal issuer under the fence

Both new real-child probes reached the actual binary and first signed a valid control reservation. They used system-aligned boot/continuous time, the real file-backed state store, the configured `issuer_load_gate`, and a generated fixture CA in a scratch secret store. Each paused only the exact child it had started, after checking PID/start token, and resumed/stopped it through exact identity/owned handles.

A sign request delivered before a 100 ms outer timeout signed after acquisition (counter 1 → 2); an unloaded CA was loaded by a cancelled reload after acquisition (0 → 1 loaded CA). E02 records the limits: these are real lower-level protocol operations, not a complete CLI timeout-to-uninstall attack or proof of an exported usable certificate.

## 5. Regression sensitivity

Each semantic mutation was applied only in the disposable worktree and restored in `finally`. All eight selected tests compiled, ran, and failed assertions with exit **101**. Compilation failures from earlier probe construction are separately listed and are not credited as regression evidence.

| Group | Semantic behavior reverted | Assertion observed |
|---|---|---|
| D01 | Omit issuer rows from the recovery snapshot | Purge reaches deletion over a CA absent from confirmation. |
| D02 | Bypass the publication admission | Publication returns `Rereserved` under the held fence. |
| D03 | Drop write-owned admissions before the blocking transaction/pause | Acquisition completes while the cancelled reservation's write is pending. |
| D04 | Give each verification caller a fresh flight map, bypassing shared coalescing | Two resumes sign four certificates instead of two. |
| D05 | Convert the forced fence refusal to an inconclusive observation | Caller receives a verification capability error instead of the fence refusal. |
| Audit A1 | Remove the whole-pipeline admission | Acquisition fails to wait for the paused activation. |
| Audit A8 | Disable the result-write compare-and-swap | Stale verification write returns `STATE_UNAVAILABLE` instead of being discarded successfully. |
| Audit L1 | Bypass the child load gate | Restart spawns another child under the held fence: spawn count 2 instead of 1. |

The original protection tests pass on restored HEAD. The E probes fail on HEAD because their fixes do not exist yet; no corrective implementation is included in this report-only review.

## 6. New findings

### W5-E01 — medium — The own-retry allowance can purge a new remote obligation

**Location:** `crates/heimdall/src/uninstall_cmd.rs:530`, especially `:560`–`:566`.

**Scenario:** an uninstall confirms a pending remote record and performs its one retry. During the stop-to-lock handoff a replacement writes a new adapter obligation for the same already-listed grant, retaining the answered record-level attempt count and stop state. `meta_unchanged_but_for` excludes this key from the exact meta comparison, then checks only root, attempts, stopped and a subset of the old grant IDs. It ignores `obligations`, per-obligation attempts/stops/kinds, effect/claim sequence, re-arm history and cap. The new recovery work is deleted.

**Probe:** `uninstall_cmd::tests::recheck3_retry_allowance_rejects_new_remote_obligation`, Cargo exit **101**. A scheduled replacement takes the real instance lock, adds a new adapter obligation and changes its sequence at the expected answered count, releases the lock, and calls the real locked purge with the retry allowance. Observed assertion: `db_exists=false`. This proves the store/lock/purge interleaving, not a naturally timed pair of CLIs or an actual remote credential creation.

**Suggested fix:** record the complete expected post-retry remote record while the original fence is held, or return that record/version from the retry transaction. Compare it exactly under the final lock, including the obligation and effect identities. Permit only the actual observed retry result, rather than any record matching its coarse counts.

### W5-E02 — medium — Timed-out child RPCs outlive their fence ownership

**Location:** `crates/issuer/src/client.rs:540`–`:547` (load permit), `:571` (load exchange), `:881`–`:921` (sign); caller timeout at `crates/app/src/managed/driver.rs:487`.

**Scenario:** a request frame reaches the real child, then the parent request future is cancelled/times out before the child processes it. The load permit, or the surrounding signing pipeline's permit, drops with the future. The child still owns the delivered work. Acquisition can complete before it reads K_ca or signs. `Unfinished` repairs the parent's lifecycle view, but does not drain/cancel the accepted child operation or retain its admission.

**Probes:** `fence::recheck3_real_issuer_late_sign_cannot_cross_fence` and `fence::recheck3_real_issuer_cancelled_load_cannot_cross_fence`, each exit **101**, repeated in `probes-final-enrollment`. With the exact test-owned child stopped, the request is delivered, the outer wait times out, and acquisition completes. Resuming the child under the held fence changes signed count **1 → 2**, or loaded CA count **0 → 1**. The child is then stopped and awaited.

The sign probe retains an eligible reservation and simulates the surrounding admission explicitly; it does not drive an entire ensure failure/abandon path. A late certificate is drained by the protocol, and none is claimed published or returned to a user. The reload probe uses the actual configured load gate and cancellation behavior directly. Its late key load does not depend on a grant remaining eligible.

**Suggested fix:** keep admission ownership with the outstanding child request until its response is consumed or that exact child has exited. Cancelling the waiter must not cancel that ownership. Alternatively end and await the exact child on an indeterminate request before releasing admission. Include both load and sign, with bounded recovery so acquisition cannot be blocked forever.

### W5-E03 — medium — Verification loses the fence holder's scope when spawned

**Location:** `crates/app/src/operations/enrollment_m03/verify.rs:93`–`:106`; `crates/app/src/operations/uninstall_fence_m03.rs:103`–`:115`.

**Scenario:** the holder drives its own deferred verification. The parent is inside `as_fence_holder`, so its admission counts nothing and `write_extension` returns none. `tokio::spawn` does not propagate that task-local scope. The verification leader therefore becomes an ordinary non-holder and its reservation is refused by the fence it legitimately owns.

**Probe:** `fence::recheck3_fence_holder_can_finish_own_verification`, exit **101**, reproduced in the final probe run. After an append result is durably deferred, the holder drives it inside the exact holder wrapper used by dispatch. Observed **zero signatures**, `SERVICE_UNAVAILABLE`, reason `uninstall_in_progress`. Ordinary post-release deferred verification still passes its checked-in tests.

**Suggested fix:** explicitly transfer authenticated, connection-scoped holder authority into the spawned leader. Couple that transfer to a lifetime/identity lease that also addresses E05; do not introduce a permanent boolean bypass into arbitrary spawned work.

### W5-E04 — medium — A replaced runtime ancestor redirects the destructive sweep

**Location:** `crates/heimdall/src/uninstall_cmd.rs:2620`–`:2625`, called from `purge_locked` at `:2520`.

**Scenario:** after the final locked inventory read, another filesystem actor replaces the runtime directory with a symlink to a different fixture directory. Checking `symlink_metadata(<run>/b)` does not reject a symlink in `<run>`: it resolves that ancestor, sees a real target `b` directory, and deletes it. The instance lock coordinates runtime writers, not directory-entry replacement.

**Probe:** `uninstall_cmd::tests::recheck3_purge_never_follows_runtime_root_replacement`, exit **101**. At the real final-read/deletion pause, the test replaces its runtime root with a link. Observed: outside marker deleted, `db_exists=false`, `purge_ok=true`. The companion `recheck3_purge_does_not_follow_nested_links` exits **0**, confirming the internal-link case works.

This requires write access to the directory entry; it is a destructive TOCTOU/containment defect, not evidence that an unrelated OS user can access an owner-only runtime directory or that Heimdall isolates hostile same-user programs.

**Suggested fix:** anchor the state/runtime roots with validated non-following directory handles and perform deletion relative to those handles; validate Windows reparse/ancestor handling equivalently. A one-time path check alone does not close the replacement interval. Refuse if safe anchoring cannot be established.

### W5-E05 — medium — A released holder keeps retry authority under a replacement fence

**Location:** `crates/app/src/operations/uninstall_fence_m03.rs:591`–`:595`, `:620`–`:644`, and the boolean holder scope at `:103`; `crates/runtime/src/dispatch.rs:492`–`:497`.

**Scenario:** holder A starts retrying two records and pauses during the first adapter call. Another in-flight request on A's connection releases the fence; B acquires it. A's future still has the task-local boolean exemption, holds no counted admission, and never rechecks ownership in its loop. It commits the first round and starts the second adapter under B's fence. IPC permits concurrent requests on a connection (`crates/ipc/src/session.rs:878`).

**Probe:** `recheck3_released_holder_must_not_continue_retry_under_new_fence` in the operation-model target, exit **101**. The actual application retry/release/acquire routes and dispatcher-equivalent holder wrapper were interleaved against the existing pending-counter adapter. After B acquired, adapter calls rose **2 → 3** and the old retry returned success. The initial version of this probe failed a fixture's absolute counter assumption; the corrected version reached and failed the ownership assertion. This is a deterministic application model, not a full IPC-wire reproduction.

**Suggested fix:** identify holder scope by connection and fence generation, retain active holder-work leases, and prevent release/reacquisition from overtaking their accepted work. Validate before starting each new retry round and before committing. A start-of-method ownership check or task-local boolean alone is insufficient.

### W5-E06 — low — The purge discards cleanup intents but leaves their stable mux socket

**Location:** `crates/heimdall/src/uninstall_cmd.rs:2621`; cleanup path at `crates/runtime/src/managed_store.rs:514`–`:518`; path constructor `crates/localenv/src/projection/content.rs:370`–`:374`.

**Scenario:** local cleanup also clears a slot's stable `<run>/mux/<destination>` path through `StoreCleanup::finish_slot` and `ConnectionSupervisor::clear_slot_path`. It is outside `<run>/b` and `<state>/managed`. A stale socket left with pending cleanup survives while its cleanup record and slot metadata are purged. This misses §17.32 item 7's condition for discarding local intents.

**Probe:** `uninstall_cmd::tests::recheck3_purge_removes_cleanup_mux_path`, exit **101**. Extends the checked-in cleanup-intent purge fixture with a socket created at the production `managed_mux_path`, closes the fixture listener, and runs the real locked purge. Purge succeeds, but the socket still exists. No live SSH master or outside server is claimed by this probe.

**Suggested fix:** enumerate the remaining cleanup-owned mux paths and clear them safely under the same anchored lock/sweep, or retain their cleanup metadata until verified absent. Extend the permanent path-coverage regression to cover `finish_slot`, not only key/certificate/binding paths.

## Commands and real exit codes

`<repo>` denotes the source clone; `<scratch>` denotes `/tmp/hm-recheck3-m03w5`. Table labels identify separately captured runs. Test output was captured with its real subprocess status and sanitized before emission. The commands used ordinary Cargo output directories.

| Run | Command | Exit | Observed result |
|---|---|---:|---|
| setup | `git -C <repo> worktree add --detach <scratch>/wt 142fe3fa6a1d8d97828f6f4e19344e7252c5e065` | 0 | Requested detached HEAD created. |
| inspect | `git rev-parse`, `git log/diff/show`, targeted `rg`, `sed`, `nl`, Python source reads | 0 | Pinned refs, production changes, callers, prior evidence and rulings read. Some exploratory `rg`/`sed` paths did not exist and reported exit 2 diagnostics inside successful navigation groups; none counted as validation. |
| versions | `rustc --version`; `cargo --version`; `uname -sm` | 0 | Rust/Cargo 1.99.1; Darwin arm64. |
| baseline | `cargo test -p heimdall --bins --test e2e_enroll_m03 --test model_operations_m03 --test e2e_managed_m03 --test integration_issuer_m03 --locked` | 101 | No such model test target in the selected heimdall package; no test ran. |
| baseline-cli | `cargo test -p heimdall --bins --test e2e_enroll_m03 --test e2e_managed_m03 --locked` | 0 | 190 binary, 98 enrollment, 16 managed tests passed. |
| baseline-runtime | `cargo test -p heimdall-runtime --lib --test model_operations_m03 --test integration_issuer_m03 --locked` | 0 | 62 runtime unit, 22 issuer integration, 44 operation-model tests passed. |
| probes-snapshot-managed | `cargo test -p heimdall --bins --test e2e_managed_m03 recheck3_ --locked` | 101 | E01 reproduced; bin failure stopped Cargo before the managed target. |
| probes-managed | `cargo test -p heimdall --test e2e_managed_m03 recheck3_ --locked` | 101 | One passed; other failed an incorrect assumption that ensure reused the degraded grant. |
| probes-enrollment | `cargo test -p heimdall --test e2e_enroll_m03 recheck3_ --locked` | 101 | Probe compilation failed: nested Option in identity comparison; no behavioral credit. |
| probes-enrollment-v2 | `cargo test -p heimdall --test e2e_enroll_m03 recheck3_ --locked` | 101 | Probe compilation failed: moved closure capture; no behavioral credit. |
| probes-enrollment-v3 | `cargo test -p heimdall --test e2e_enroll_m03 recheck3_ --locked` | 101 | Production-effects control passed; E03 reproduced; real-child start was inconclusive at a 100 ms internal bound. |
| probe-real-child-v4 | `cargo test -p heimdall --test e2e_enroll_m03 recheck3_real_issuer --locked` | 101 | E02 sign reproduced with a 5 s child bound and 100 ms outer cancellation. |
| probe-real-load | `cargo test -p heimdall --test e2e_enroll_m03 recheck3_real_issuer_cancelled_load --locked` | 101 | E02 late CA load reproduced. |
| probes-purge-races | `cargo test -p heimdall --bins recheck3_purge_ --locked` | 101 | Nested-link control passed; E04 ancestor-replacement deletion reproduced. |
| mutation-D01 | `cargo test --locked -p heimdall --bins recheck2_purge_refuses_new_ca_from_replacement_that_already_stopped` | 101 | Compiled; intended new-CA deletion assertion failed. |
| mutation-D02 | `cargo test --locked -p heimdall-runtime --test model_operations_m03 recheck2_publication_must_not_rereserve_under_held_fence` | 101 | Compiled; returned re-reservation under fence. |
| mutation-D03 | `cargo test --locked -p heimdall-runtime --test model_operations_m03 recheck2_cancelled_reservation_keeps_admission_until_store_write_finishes` | 101 | Compiled; acquisition overtook the pending write. |
| mutation-D04 | `cargo test --locked -p heimdall --test e2e_enroll_m03 recheck2_deferred_verification_is_not_duplicated_by_two_steps` | 101 | Compiled; 4 signatures rather than 2. |
| mutation-D05 | `cargo test --locked -p heimdall --test e2e_enroll_m03 verification_fence_refusal_is_returned_and_changes_no_evidence` | 101 | Compiled; wrong verification error instead of fence refusal. |
| mutation-A1 | `cargo test --locked -p heimdall --test e2e_enroll_m03 acquisition_waits_for_in_flight_activation` | 101 | Compiled; acquisition did not wait for activation. |
| mutation-A8-CAS | `cargo test --locked -p heimdall --test e2e_enroll_m03 verification_result_write_records_only_the_run_it_started_from` | 101 | Compiled; stale writer returned STATE_UNAVAILABLE. |
| mutation-L1 | `cargo test --locked -p heimdall-issuer --test integration_issuer_child broken_link_restart_under_a_held_fence_loads_nothing_until_the_lift` | 101 | Compiled; child restarted under fence. |
| baseline-store-issuer | `cargo test -p heimdall-store -p heimdall-issuer --lib --locked` | 0 | 22 issuer unit and 21 store unit tests passed. |
| probe-holder-retry | `cargo test -p heimdall-runtime --test model_operations recheck3_released_holder --locked` | 101 | Failed fixture counter assumption; no ownership conclusion credited. |
| probe-holder-retry-v2 | `cargo test -p heimdall-runtime --test model_operations recheck3_released_holder --locked` | 101 | E05 reproduced: another adapter call after replacement acquisition. |
| probes-managed-corrected | `cargo test -p heimdall --test e2e_managed_m03 recheck3_ --locked` | 0 | Both corrected managed concurrency probes passed. |
| probes-final-enrollment | `cargo test -p heimdall --test e2e_enroll_m03 recheck3_ --locked` | 101 | Production-effects control passed; E02 sign/load and E03 reproduced. |
| probe-purge-mux | `cargo test -p heimdall --bins recheck3_purge_removes_cleanup_mux_path --locked` | 101 | E06 reproduced: cleanup mux socket remained. |
| restore | `python3: restore five probe files from git show HEAD, then git diff --exit-code and git status --porcelain` | 0 | All five temporary probe files restored; tracked diff and status clean. |
| final-clippy | `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | Workspace/all-targets Clippy passed with warnings denied. |
| final-fences | `cargo test -p heimdall --test e2e_enroll_m03 fence:: --locked` | 0 | 14 fence e2e regressions passed on restored HEAD. |
| baseline-issuer-child | `cargo test -p heimdall-issuer --test integration_issuer_child --locked` | 0 | 36 issuer-child integration tests passed. |
| final-app-fences | `cargo test -p heimdall-app --lib uninstall_fence --locked` | 0 | 5 application fence tests passed. |
| final-retry-route | `cargo test -p heimdall-runtime --test model_operations uninstall_fence_retry_is_one_ordinary_round --locked` | 0 | Ordinary retry/cap/stopped/entry-ownership regression passed. |
| final-bins | `cargo test -p heimdall --bins --locked` | 0 | 190 binary tests passed on restored HEAD. |
| prototype-hygiene | `zsh -c 'setopt nonomatch; du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist'` | 1 | No prototype output directories matched; du reported missing patterns. |
| root-target-size | `du -sh target` | 0 | Measured scratch build output; all removed with worktree. |

The probe-generation/adjustment Python commands exited 0. `python3 <scratch>/mutations.py` exited 0 after recording eight individual Cargo exits of 101 and restoring each mutation. Sanitized process inspections emitted only selected PID/parent/elapsed/executable-name fields, and found no matching review test executable at the inspected post-test point. Captured validation logs contained zero canary-redaction hits.

## Changed files, validation limits and cleanup

- **Persistent changed file:** this external report only. Temporary probes touched `crates/heimdall/src/uninstall_cmd.rs`, `tests/e2e/enroll_m03.rs`, `tests/e2e/enroll_m03/fence.rs`, `tests/e2e/managed_m03.rs` and `tests/model/operations.rs`. Mutations additionally touched the production files identified in the sensitivity table. All were restored before final validation. No evidence record was written inside the repository.
- **blocked:** native Windows, Linux and WSL tests; those native hosts/harnesses were unavailable to this review. Reading standard-library-based code does not close native lock, secure-store or reparse-point claims.
- No full workspace test suite, release-build gate, product-file/login-keychain test, physical session-lock test, power-loss campaign, full crash matrix, natural two-CLI race, IPC-wire holder-release race or concurrency soak was performed. Clippy covered all workspace targets; targeted suites and scheduled interleavings supplied the behavioral evidence stated above.
- E01/E04/E06 use actual store/lock/purge helpers with scheduled fixture mutations; E05 uses application routes with a fixture adapter. E02 uses actual child processes and protocol behavior but a scratch secret store, with the sign-operation limit stated in its finding. E03 uses the actual holder wrapper and deferred-verification route.
- The root-replacement probe required filesystem write access to the entry it replaced. No cross-user privilege escalation, private-key export, real remote mutation or published late certificate is claimed.

**Cleanup confirmed, exit 0.** `git -C <repo> worktree remove --force /tmp/hm-recheck3-m03w5/wt` removed the detached worktree and its complete 10G `target/`. Exact-path Python removal of `/tmp/hm-recheck3-m03w5` completed, exit 0. Assertions confirmed the scratch root and worktree registration are absent, the source checkout is clean, and this report remains. Before removal, the detached checkout was clean at the pinned HEAD and zero runtime keychain files existed under the scratch root. No pre-existing process was stopped.

| Cleanup command | Exit | Observed result |
|---|---:|---|
| Python exact-head/status/report/keychain assertions | 0 | Pinned HEAD, clean source and scratch checkouts, six findings, zero scratch keychains, no home paths in report. |
| `git -C <repo> worktree remove --force /tmp/hm-recheck3-m03w5/wt` | 0 | Worktree and entire build output removed. |
| Python exact-path scratch removal and worktree/status/report assertions | 0 | Scratch absent, unregistered, source checkout clean, report retained. |

Not checked: native Windows/Linux/WSL, release gates, product-keychain behavior and exhaustive crash/concurrency cases.
Risk: the six remaining findings prevent a merge verdict despite the passing original regressions and Clippy.
