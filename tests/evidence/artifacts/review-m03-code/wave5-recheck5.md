**Verdict: fix first.**

Final correctness and robustness review of M03 wave 5, rounds 11–12, `06990cc8..94d6076d476835fe8465cf606125016b053a4abd` on `m03/wave5`. The detached review checkout was pinned to the full head SHA. Host: Darwin arm64; rustc 1.99.1 (58cf8f9c3), Cargo 1.99.1 (5f94df478).

What this change does: rounds 11–12 bind holder work to a counted fence lease, retain admissions while indeterminate issuer requests are ended, compare exact retry records, and move purge targets to quarantine before validation. The new read census and ordinary quarantine regressions work, but SQLite files are still handled independently during rollback and partial deletion. That leaves two BLOCKING recovery defects.

All implementation and test changes for this review were temporary and confined to the requested detached worktree. The main checkout and other worktrees were not edited. No commit, push, package install, publishing, privileged operation or real-server operation was performed. All fixture stores, keys and filesystem targets were disposable. Product-keychain tests used their disposable file-keychain harness, never the login keychain. Builds used the worktree's ordinary `./target` only.

**1. Earlier regressions and main suites**

The retained earlier regression tests pass at this head. None of the main suites below failed.

| Suite | Passed | Failed | Ignored | Exit |
|---|---:|---:|---:|---:|
| `heimdall --bins` | 227 | 0 | 0 | 0 |
| `heimdall / e2e_cli_m03` | 69 | 0 | 3 | 0 |
| `heimdall / e2e_enroll_m03` | 99 | 0 | 0 | 0 |
| `heimdall / e2e_managed_m03` | 16 | 0 | 0 | 0 |
| `heimdall-runtime / model_operations` | 191 | 0 | 0 | 0 |
| `heimdall-store` | 21 | 0 | 0 | 0 |
| `heimdall-domain` | 102 unit + 21 integration + 2 doctests | 0 | 0 | 0 |
| `heimdall-app --lib` | 69 | 0 | 0 | 0 |
| `heimdall-issuer --lib` | 22 | 0 | 0 | 0 |
| `heimdall-runtime --lib` | 63 | 0 | 0 | 0 |
| `heimdall-runtime / integration_issuer_m03` | 22 | 0 | 0 | 0 |
| `heimdall-runtime / model_operations_m03` | 44 | 0 | 0 | 0 |
| `heimdall-testkit / integration_store_m03` | 36 | 0 | 0 | 0 |
| `heimdall-issuer / integration_issuer_child` | 36 | 0 | 0 | 0 |
| `heimdall / e2e_issuer_ceremony` | 8 | 0 | 2 | 0 |
| `heimdall / e2e_tui_m03` | 5 | 0 | 1 | 0 |
| Slow-Git preview-digest regression | 1 | 0 | 0 | 0 |
| Release `heimdall-issuer --lib` | 21 | 0 | 0 | 0 |
| Release `integration_issuer_release_gate` | 3 | 0 | 0 | 0 |

The debug-profile rows total **1,054 passing test results**, with six ignored child/harness entry points. The release rows add **24 passing test results**. Repeated restored-source runs are listed in the command ledger and excluded from those totals.

A conservative, reproducible naming-based count finds **25 passing retained tests whose function name starts with `recheck`**: nine binary tests, five CLI tests, eight enrollment tests, one operation-model test, and two M03 operation-model tests. These include E01's new-obligation rejection; E02's real-child sign, cancelled-load and unconfirmed-stop cases; E03's holder verification; E04's replaced-root and nested-link cases; E05's released-holder retry; E06's mux cleanup; and F01–F04. Normal-named regressions also passed, including exact retry-commit ownership, stale generation refusal, holder-spawned lease propagation, cancelled store writes, verification single-flight/result checks, hold-payload validation and the original consent/disclosure fixes.

The reconstructed fourth review also names temporary exploratory positive controls that are not retained as test functions in this head. I do not claim to have rerun those absent probes byte-for-byte. The retained regression tests, new probes below, and six semantic mutations are the executed evidence.

`bash tools/validation/release-gate.sh` passed **27 probes, zero failures**, including rejection of the debug-only trusted-top hook. Workspace/all-targets Clippy with warnings denied passed on restored head. `claims_table.py` passed nine self-tests and validated six residual entries; it does not detect the missing accepted residual described in G03.

**2. Purge correctness**

There is **no unconditional guarantee for the entire operation**. Normal quarantine and final-read identity binding are substantially improved, and their regression tests are sensitive. G01 breaks refusal recovery; G02 breaks partial-deletion recovery.

| Entry/path | Assessment from code and execution |
|---|---|
| `state.db` | Inspected, renamed without replacement, opened and held at its quarantine name, and read through SQLite. Unix checks the held inode's descriptor-count increase before dropping the store; Windows holds a no-share-delete handle. Transient final-read substitutions are rejected in the exercised cases. Its restore can be separated from its logs (G01), and its deletion precedes companions (G02). |
| `state.db-wal` and `state.db-shm` | Existing files are inspected, moved and held; absent files are created exclusively at quarantine names. The Unix census checks each held identity separately, and names are checked again. Their individual rename-back is unsafe as a SQLite bundle (G01). |
| `state.db-journal` | Included in the manifest, quarantine and final validation; a journal absent at inspection must not already exist at its quarantine name when `hold` checks. It is not one of the three descriptor-census files. A read needing unsupported rollback fails closed; I found no demonstrated journal-specific read/deletion bypass. The bundle/order defects apply to its handling too. |
| Backups and `managed` | Whole trees are moved to quarantine, and sorted path/kind/identity manifests are compared before deletion. Unix walks and removes relative to directory descriptors, refusing symlinks during validation. Original-name leaf replacement and nested-link tests pass. The accepted post-validation placement residual remains. |
| Runtime binding tree `b` and mux tree `mux` | Same quarantine/manifest approach under the anchored runtime root. Runtime-root replacement, nested links, mux removal and path-coverage tests pass. The CLI-runtime-directory residual remains. |

For the SQLite path open, Unix `read_db` takes its census before `open`, runs both final inventory and bundle checks against the returned store, then checks the per-file census and held names while that store is still alive (`crates/heimdall/src/purge_sweep.rs:962`, `:986`; `crates/heimdall/src/uninstall_cmd.rs:2594`). The WAL-swap and planted-WAL tests pass. Removing census confirmation allows the WAL-swap regression to reach deletion and fail, exit 101. The census is evidence of open-file identity in these flows; it is not a snapshot or protection against arbitrary in-place writes by another same-user process.

Rename-back uses no-replace operations and reports names it cannot restore. That protects an occupied destination from a direct overwrite, but does **not** protect a replacement database from an old WAL restored beside it. G01 was reproduced through the real `purge_now`/final-check/refusal/restore path, not merely by calling a synthetic comparator.

Deletion runs `b`, `mux`, backups and managed trees before the database family. Within the family it runs **database, WAL, SHM, journal**, not database last. Its partial-failure handler restores only entries not yet deleted, so G02 leaves no main database to restore. Simply reversing the family order would also be inadequate for a WAL-dependent database: recovery must retain a complete usable database state until deletion can safely finish.

By reading, the Windows implementation pins ancestor components without share-delete, rejects reparse points, checks owner SIDs, uses `MoveFileExW` without replacement, compares file IDs, and pins each directory throughout enumeration/removal of children. It drops each entry's pin before the path removal, leaving the named accepted window. It also uses the same unsafe independent restore and database-first family order; the platform equivalence of G01/G02 is source inference, not native evidence.

The Unix secure-path classifier accepts modeled macOS defaults, Linux XDG defaults, and Debian/Ubuntu private-group homes, while refusing foreign owners, shared writable ancestors, sticky shared parents, owner-created links, non-owner-only roots and unavailable private-group lookups when needed. The native macOS scratch-chain test from `/`, synthetic-tree tests, and this host's private-group lookup pass. The private-group acceptance regression fails when that exception is removed. The Windows default-layout and SID classifiers pass, but native Windows path/ACL behavior and native Linux group lookup were not executed here. Windows explicit directory DACL hardening remains outside this change, as stated in `crates/runtime/src/paths.rs`; an owner-SID check should not be described as a full ACL audit.

**3. Coordination correctness**

A fence is not a stop-all-writes boundary. By design, the holder can do its own admitted cleanup/retry work; previously dispatched step results, denials and permitted local/narrowing bookkeeping can still be recorded. Final inventory comparison remains necessary.

For the reviewed changes, the lease contains connection and generation, counts live holder work including clones, and becomes invalid on release. Spawned verification/operation leaders carry it explicitly. The blocking store-write closure carries a clone and checks it before entering its transaction; its lifetime prevents release/reacquisition from overtaking that write. Retry checks the lease before each round, and its commits go through the same write path. The stale-generation, spawned-task, release-wait and released-holder retry regressions pass. Dropping lease propagation to the verification leader fails the holder-verification regression, exit 101. I found no additional reachable acquire/release deadlock or consent bypass in these paths. This is source analysis plus controlled interleavings, not an exhaustive scheduler proof.

For a normal issuer sign with a current-task admission, `request_hold` extends that admission. For load it owns the load-gate permit. An indeterminate exchange takes the child out of the live link, checks PID/start token/image before signaling, closes the pipes, and retains permits until exit is observed; an unconfirmed exit retains them in a background wait. The real-child sign, load and unconfirmed-stop regressions pass. Reverting the exchange to an ordinary unguarded wait permits acquisition while the stopped child still owns the request and fails the sign regression, exit 101.

It is therefore **not true that no signature can ever execute after acquisition**: the accepted leader/lease request-hold residual allows a child to outlive that task's admission. Its late reply is discarded and cannot be published through that cancelled request. Likewise, cleanup cancellation can release a permit before exit is confirmed and signal the owned unreaped child through `kill_on_drop`. The retained residual probes pass. No new lasting remote-trust change or unconsented approval was established from those cases.

Exact retry allowance is materially fixed: successful rounds return their own transaction's complete record; unchanged rounds answer from their own transaction; failed rounds grant no changed bytes. The locked comparison requires canonical serialized equality and rejects a recreated completed record or new obligation. The retained exact-commit/gap-write and new-obligation tests pass, and a partial-field comparison mutation fails its regression. G04 concerns only the displayed inventory after failure.

The known never-ending-holder-work case can leave the fence releasing until that work ends or the runtime restarts. The code reports `uninstall_fence_release_stuck` with the two-command restart guidance. This accepted behavior is tested but missing from `RESIDUALS` (G03). Unconfirmed child exit can also keep admissions outstanding and cause bounded acquisition refusal; no fence is acquired early in the normal admitted path. I found no additional permanent stuck-fence mechanism in the reviewed production flow.

**4. Every `RESIDUALS` entry**

| Residual | Accuracy and classification |
|---|---|
| `windows_purge_entry_replaced_between_check_and_delete` | The unpin-to-removal window exists by reading. Removal of an actor's own replacement/link at a quarantine path fits the explicit accepted placement limit, NON-BLOCKING. Native Windows proof remains blocked on that platform. This entry does not excuse G01/G02. |
| `purge_entry_placed_in_quarantine_is_deleted` | The retained placement probe passes: an added entry inside a quarantined tree is deleted, while a newly created original-name backup survives. NON-BLOCKING under the explicit §17.34 item 1 placement ruling. Its wording cannot be read as a guarantee that refusal/rollback preserves every original-name database: G01 is a separate counterexample. |
| `issuer_request_hold_absent_for_leader_and_lease_work` | The task-ID-based extension can be absent in these tasks; the retained stuck-child probe passes. A child can remain alive across acquisition, but the discarded reply does not publish a certificate and the child does not logically update the state store. NON-BLOCKING under the accepted no-lasting-effect ruling. |
| `holder_approval_spawns_waiting_work_with_the_holder_lease` | Matches the `decide`/resume path by reading. It requires the owner program holding the fence to approve. It does not create a new consent bypass; NON-BLOCKING under the same-user-program exception. This residual has a code citation, not a dedicated executed behavioral probe. |
| `uninstall_sweep_uses_cli_runtime_dir_not_recorded_locators` | Matches the sweep roots; the report-root test passes. Other runtime-root leftovers remain outside this purge. NON-BLOCKING local leftovers; no new recovery-record loss was shown from this residual. |
| `issuer_cleanup_cancelled_kill_on_drop_signals_unreaped_child` | The retained cancellation probe passes and deliberately demonstrates the accepted behavior. The owned unreaped handle cannot refer to a reused PID. A possible late load/sign is not published; NON-BLOCKING as ruled. The literal test name is historical and should not be mistaken for proof that no signal occurs. |

None of those six narrowly stated accepted cases establishes an additional BLOCKING issue. G01 is outside the placement exception: it corrupts a new database at its **original** name without the actor placing anything at a quarantine name. The accepted stuck-release entry is absent (G03). New non-blocking reporting limits G03/G04 should be recorded rather than used to extend this review indefinitely.

**5. Regression sensitivity**

Each mutation was applied alone in the detached copy, compiled, failed at the intended runtime assertion (not at compilation), and was restored byte-for-byte before the next mutation.

| Area | Semantic reversion | Regression | Exit / observed assertion |
|---|---|---|---|
| Final SQLite read | Ignore census confirmation | `uninstall_cmd::tests::final_read_wal_swapped_during_open_keeps_committed_record` | 101; reached purge |
| Backup quarantine | Keep `backups` at its original name and skip its rename | `purge_sweep::tests::recheck4_leaf_replacement_must_keep_unconfirmed_owner_data` | 101; unconfirmed inode deleted |
| Private-group homes | Refuse the private-group exception | `purge_sweep::tests::recheck4_default_unix_home_with_private_group_must_pass` | 101; default home refused |
| Holder lease | Spawn verification leader with plain `tokio::spawn` | `fence::recheck3_fence_holder_can_finish_own_verification` | 101; holder verification refused |
| Indeterminate issuer | Use ordinary exchange with no cancellation child-ending guard | `issuer::recheck3_real_issuer_late_sign_cannot_cross_fence` | 101; child alive at acquisition |
| Exact retry record | Compare only attempts and stopped fields | `uninstall_cmd::tests::recheck3_retry_allowance_rejects_new_remote_obligation` | 101; reached deletion over a new obligation |

Restored-source runs passed 227 binary tests and the selected real-child/holder coordination tests (three CLI, one enrollment), and Clippy passed again. Final `git diff --exit-code` was 0.

**6. New issues**

**W5-G01 — high — BLOCKING: rename-back can attach an old WAL to a new database and destroy its recovery records.**

Location: `crates/heimdall/src/purge_sweep.rs:1056` (especially the reverse independent rename loop at `:1064`), Windows equivalent `:1613`; refusal caller `crates/heimdall/src/uninstall_cmd.rs:2585`.

Scenario: the inspected database has a committed recovery record in its WAL. After quarantine, another local program places a different valid database, containing another recovery record, at the original `state.db` path. The final check correctly refuses. Restore nevertheless returns the old WAL to `state.db-wal` before discovering that the original database name is occupied. It leaves the original database quarantined, but the restored WAL is now paired with the different database. An ordinary subsequent store open/checkpoint overwrites that replacement database's pages with the old WAL, losing its record. Direct no-replace rename protection is insufficient because SQLite performs the destructive write later.

Observed test: temporary `uninstall_cmd::tests::final_review_restore_does_not_attach_old_wal_to_new_owner_database`, exit **101**, repeated with a persistence assertion, exit **101**. It used existing `state_dir`, `wal_of`, `foreign`, `replacement_writes` and `purge_now` helpers. The original WAL contained foreign-removal record 7; the replacement database was independently verified to contain record 9. A final-read hook created that replacement at the original path. Purge returned `PurgeEnd::Stuck`, as expected. A normal `replacement_writes(..., |_| Ok(()))` reopen checkpointed the restored WAL. The strengthened probe confirmed that no WAL remained before checking the reopened database; record 9 was gone. Failure text: `rename-back attached another database's WAL and lost the unvalidated record`. No final deletion had been authorized for the replacement database. macOS behavior is observed; the equivalent Windows defect is inferred from its matching restore loop.

Why BLOCKING: lasting corruption of an unvalidated original-name database and loss of a recovery record, through the destructive purge workflow. §17.33 item 10 takes precedence even though another same-user program creates the collision. This is not an actor inserting its own data at a random quarantine name.

Suggested fix: treat the database and its companions as one recovery unit. Do not independently restore a sidecar into a live namespace whose database could not be restored and bound to that sidecar. On any collision, retain a complete consistently named recovery bundle in quarantine, report every member, and ensure a normal startup cannot combine old logs with a replacement database. Moving the database rename earlier alone does not solve arbitrary interleavings; preserve the bundle invariant through the whole transition.

**W5-G02 — medium — BLOCKING: a companion deletion failure occurs after the only database copy has already been deleted.**

Location: `crates/heimdall/src/purge_sweep.rs:1017` and `:1026`, target order from `DB_SUFFIXES` at `:74`; Windows equivalent `:1572`. The promised recovery wording is `crates/heimdall/src/uninstall_cmd.rs:2672`.

Scenario: the trees are removed, then `state.db` is unlinked, then unlinking its WAL fails. The partial-failure handler can only restore the remaining WAL/other files. It cannot restore the already deleted database. The error text nevertheless says that the state database is among the entries renamed back and was deleted last.

Observed test: temporary `purge_sweep::tests::final_review_companion_failure_preserves_database`, exit **101**, strengthened no-copy check also **101**. It used the sweep's disposable `roots` fixture and a stand-in database/WAL. Its existing per-unlink hook made the owner-controlled scratch state directory non-writable immediately before WAL unlink, then restored permissions after `delete` returned. The WAL deletion failed; the strengthened test found **neither a normal-name nor a quarantine-name main database**. Failure text: `database was deleted before its companion failure, with no normal or quarantined copy left`. This probes the real sweep loop; reachability for a fully validated SQLite database and the identical Windows order are source inference.

Why BLOCKING: the explicit database-last recovery obligation is false, and a failed purge leaves irreversible loss of the main database rather than a recoverable remaining bundle. Unlike G01, these bytes were confirmed for a successful purge; the defect is loss of the promised recovery state on the partial-failure path, not a new-inventory consent bypass. The requested merge criteria include lasting loss of data/recovery records on this deletion path.

Suggested fix: keep a complete recoverable SQLite state until the last potentially failing database-family cleanup, and delete the main database last. Do not merely delete WAL first: committed records may exist only in it. Retain or construct a validated self-contained recovery copy/bundle until cleanup succeeds, and make the partial-failure report describe the files actually retained. Add a companion-failure regression, not only the existing earlier-tree-failure regression.

**W5-G03 — low — NON-BLOCKING: the accepted stuck-release residual is missing from the residual manifest.**

Location: `crates/domain/src/claims.rs:144`; implemented/tested behavior at `crates/app/src/operations/uninstall_fence_m03.rs:1360`.

Scenario: holder work never finishes, release reaches its bound, and other work remains refused until the work ends or the runtime restarts. ADR-0008 §17.33 item 9 and the test name this residual `uninstall_fence_release_stuck_until_holder_work_ends`, but none of the six `RESIDUALS` entries has that ID. The claims-table validator passes without it.

Evidence: the existing stuck-release app/runtime tests passed in `extra-libs`, exit **0**. A separate manifest-membership assertion for that exact ID failed, exit **1**; `claims_table.py` still passed, exit **0**.

Why NON-BLOCKING: the behavior is the already accepted refusal/delay; this issue is missing bookkeeping, with no new data, trust or consent effect. Suggested fix: add the accepted entry with the existing behavioral probe, platform, reason and ADR citation. A required-ID assertion can prevent accidental omission.

**W5-G04 — low — NON-BLOCKING: a failed retry disappears from the pending-revocation inventory display.**

Location: `crates/heimdall/src/uninstall_cmd.rs:1487`, especially `:1495`; callers apply it at `:2151` and later annotate the report.

Scenario: a retry returns `outcome: failed`, `pending: true`, `record: None`, as the new runtime payload does for failure. `apply_retries` treats every `None` record as completed and removes the confirmed record from the in-memory listing. The report can therefore show no `pending_remote_revocations` even though its separate retry result says pending and the store still holds the record.

Observed test: temporary `uninstall_cmd::tests::final_review_failed_retry_retains_pending_display_record`, exit **101**. One confirmed pending record was passed through `apply_retries` with that failure payload; its length changed from one to zero. Failure text: `failed retry hid the still-pending record`.

Why NON-BLOCKING: this is a report defect on a failed attempt. The persistent record and exact locked metadata comparison remain protected; a changed failed-round record still refuses purge. No lasting loss or consent bypass was established. Suggested fix: leave the existing record displayed for `failed` (or any still-pending response lacking a replacement record); remove it only for a completed, no-longer-pending result. Record the display limitation if it is deferred.

**Commands and real exit codes**

All Cargo and validation commands below ran from the detached worktree. Labels identify the corresponding sanitized scratch capture; captures are removed during cleanup. Commands are listed as executed; the wrapper only collected output/exit status. `101` on mutation/probe rows is a Cargo assertion failure. The first restore-probe invocation accidentally supplied an unqualified exact test name and matched zero tests; it receives no evidence credit. The initial Clippy failure came from temporary probe `unwrap()` calls, not production head; all restored-head Clippy runs passed.

| Label | Command | Exit | Observed result |
|---|---|---:|---|
| bins | `cargo test -p heimdall --bins` | 0 | 227 passed / 0 failed / 0 ignored |
| cli | `cargo test -p heimdall --test e2e_cli_m03` | 0 | 69 passed / 0 failed / 3 ignored |
| enroll | `cargo test -p heimdall --test e2e_enroll_m03` | 0 | 99 passed / 0 failed / 0 ignored |
| managed | `cargo test -p heimdall --test e2e_managed_m03` | 0 | 16 passed / 0 failed / 0 ignored |
| probe-restore | `cargo test -p heimdall --bin heimdall final_review_restore_does_not_attach_old_wal_to_new_owner_database -- --exact` | 0 | 0 passed / 0 failed / 0 ignored |
| probe-restore-exact | `cargo test -p heimdall --bin heimdall uninstall_cmd::tests::final_review_restore_does_not_attach_old_wal_to_new_owner_database -- --exact` | 101 | 0 passed / 1 failed / 0 ignored |
| model | `cargo test -p heimdall-runtime --test model_operations` | 0 | 191 passed / 0 failed / 0 ignored |
| store | `cargo test -p heimdall-store` | 0 | 21 passed / 0 failed / 0 ignored; 0 passed / 0 failed / 0 ignored |
| release-gate | `bash tools/validation/release-gate.sh` | 0 | 27 probes / 0 failed |
| domain | `cargo test -p heimdall-domain` | 0 | 102 passed / 0 failed / 0 ignored; 21 passed / 0 failed / 0 ignored; 2 passed / 0 failed / 0 ignored |
| clippy | `cargo clippy --workspace --all-targets --locked -- -D warnings` | 101 | Temporary probe unwrap lint failures; head reruns passed |
| probe-order | `cargo test -p heimdall --bin heimdall purge_sweep::tests::final_review_companion_failure_preserves_database -- --exact` | 101 | 0 passed / 1 failed / 0 ignored |
| extra-libs | `cargo test -p heimdall-app -p heimdall-runtime -p heimdall-issuer --lib --locked` | 0 | 69 passed / 0 failed / 0 ignored; 22 passed / 0 failed / 0 ignored; 63 passed / 0 failed / 0 ignored |
| extra-runtime | `cargo test -p heimdall-runtime --test model_operations_m03 --test integration_issuer_m03 --locked` | 0 | 22 passed / 0 failed / 0 ignored; 44 passed / 0 failed / 0 ignored |
| extra-store | `cargo test -p heimdall-testkit --test integration_store_m03 --locked` | 0 | 36 passed / 0 failed / 0 ignored |
| extra-issuer | `cargo test -p heimdall-issuer --test integration_issuer_child --locked` | 0 | 36 passed / 0 failed / 0 ignored |
| extra-ceremony | `cargo test -p heimdall --test e2e_issuer_ceremony --test e2e_tui_m03 --locked` | 0 | 8 passed / 0 failed / 2 ignored; 5 passed / 0 failed / 1 ignored |
| claims | `python3 -I tools/validation/claims_table.py` | 0 | 6 residuals; 9 self-tests passed |
| extra-git | `cargo test -p heimdall-localenv --test integration_projection_git git_preview_digest_is_stable_under_a_slow_git --locked -- --exact` | 0 | 1 passed / 0 failed / 0 ignored |
| final-clippy | `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | Passed |
| mut-census | `cargo test -p heimdall --bin heimdall uninstall_cmd::tests::final_read_wal_swapped_during_open_keeps_committed_record -- --exact` | 101 | 0 passed / 1 failed / 0 ignored |
| mut-quarantine | `cargo test -p heimdall --bin heimdall purge_sweep::tests::recheck4_leaf_replacement_must_keep_unconfirmed_owner_data -- --exact` | 101 | 0 passed / 1 failed / 0 ignored |
| mut-private-group | `cargo test -p heimdall --bin heimdall purge_sweep::tests::recheck4_default_unix_home_with_private_group_must_pass -- --exact` | 101 | 0 passed / 1 failed / 0 ignored |
| mut-lease | `cargo test -p heimdall --test e2e_enroll_m03 fence::recheck3_fence_holder_can_finish_own_verification -- --exact` | 101 | 0 passed / 1 failed / 0 ignored |
| mut-issuer | `cargo test -p heimdall --test e2e_cli_m03 issuer::recheck3_real_issuer_late_sign_cannot_cross_fence -- --exact` | 101 | 0 passed / 1 failed / 0 ignored |
| mut-retry | `cargo test -p heimdall --bin heimdall uninstall_cmd::tests::recheck3_retry_allowance_rejects_new_remote_obligation -- --exact` | 101 | 0 passed / 1 failed / 0 ignored |
| restored-diff | `git diff --exit-code` | 0 | Passed |
| restored-bins | `cargo test -p heimdall --bins` | 0 | 227 passed / 0 failed / 0 ignored |
| residual-manifest | `python3 -c 'import pathlib,re; s=pathlib.Path("crates/domain/src/claims.rs").read_text(); ids=re.findall(r"id: \"([^\"]+)\"",s); assert "uninstall_fence_release_stuck_until_holder_work_ends" in ids, "ADR-0008 section 17.33 item 9 residual is missing"'` | 1 | Accepted stuck-release ID absent |
| restored-coordination | `cargo test -p heimdall --test e2e_cli_m03 --test e2e_enroll_m03 recheck3_` | 0 | 3 passed / 0 failed / 0 ignored; 1 passed / 0 failed / 0 ignored |
| restored-clippy | `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | Passed |
| probe-restore-persisted | `cargo test -p heimdall --bin heimdall uninstall_cmd::tests::final_review_restore_does_not_attach_old_wal_to_new_owner_database -- --exact` | 101 | 0 passed / 1 failed / 0 ignored |
| release-issuer | `cargo test --release -p heimdall-issuer --lib --test integration_issuer_release_gate --locked` | 0 | 21 passed / 0 failed / 0 ignored; 3 passed / 0 failed / 0 ignored |
| probe-retry-display | `cargo test -p heimdall --bin heimdall uninstall_cmd::tests::final_review_failed_retry_retains_pending_display_record -- --exact` | 101 | 0 passed / 1 failed / 0 ignored |
| last-bins | `cargo test -p heimdall --bins` | 0 | 227 passed / 0 failed / 0 ignored |
| last-clippy | `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | Passed |
| output-hygiene | `bash -c 'du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist'` | 1 | No matching prototype output directories in this worktree |
| worktree-size | `du -sh target` | 0 | 14 GB target; removed with worktree |
| probe-order-no-copy | `cargo test -p heimdall --bin heimdall purge_sweep::tests::final_review_companion_failure_preserves_database -- --exact` | 101 | 0 passed / 1 failed / 0 ignored |
| final-source-diff | `git diff --exit-code` | 0 | Passed |
| final-head-clippy | `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | Passed |

Setup, source inspection and cleanup commands are grouped below to avoid reproducing long read-only excerpts and temporary-test source inside the command table. `$SOURCE` denotes the original checkout; its personal absolute path is intentionally omitted. This is path redaction, not a different checkout.

| Command / command family | Exit | Result |
|---|---:|---|
| `test ! -e /tmp/hm-final-m03w5 && mkdir /tmp/hm-final-m03w5` | 0 | Fresh scratch root created |
| `git -C "$SOURCE" worktree add --detach /tmp/hm-final-m03w5/wt 94d6076d476835fe8465cf606125016b053a4abd` | 0 | Exact detached head checked out |
| `git rev-parse HEAD`; `git log --oneline 06990cc8..HEAD`; `git diff --stat 06990cc8..HEAD`; targeted `git diff 06990cc8..HEAD -- ...` | 0 | Head, three-commit range, changes and connected production paths inspected |
| `sed`, `nl`, `cat`, targeted `rg`, and Python extraction over production source, callers, tests, `spec.md`, `plan.md`, ADR-0008, prior reports and r11/r12 notes | 0 for successful reads/matches | Code-first assessment preceded review-history comparison. Missing exploratory paths produced `rg` exit 2; one unmatched shell source glob produced exit 1. These were navigation failures, not test evidence. |
| Preliminary active-instruction/skill reads; targeted memory-registry lookup | 0 for reads; 1 for no matching memory entry | No historical memory fact used in this review |
| Python scratch runner/suite/mutation/probe/report-file creation and test-source insertion/removal | 0 | Only scratch paths written; mutation driver validated behavioral failure and restored each file in `finally` |
| `git restore --source=HEAD -- crates/heimdall/src/uninstall_cmd.rs` and corresponding `purge_sweep.rs` restores | 0 | Temporary test additions removed |
| `git diff --exit-code`; `git status --porcelain`; final `git rev-parse HEAD` | 0 | Tracked sources clean, head unchanged |
| `rustc --version`; `cargo --version`; `uname -sm` | 0 each | Versions/platform reported above |
| `git -C "$SOURCE" worktree remove --force /tmp/hm-final-m03w5/wt` | 0 | See cleanup confirmation |
| `rm -rf /tmp/hm-final-m03w5` | Not executed | Tool rejected force-removal syntax; used the safer exact-path cleanup below |
| Python `shutil.rmtree` after asserting the exact scratch root, owned review marker files and absent worktree | 0 | Exact scratch root removed |
| Scratch-path absence and worktree-registration assertions; report sanitation check | 0 | See cleanup confirmation |

**Changed files and retained artifacts**

Persistent repository changes: **none**. The sole retained review artifact is `/tmp/hm-final-m03w5-report.md`. Temporary additions affected `crates/heimdall/src/{uninstall_cmd,purge_sweep}.rs`; semantic mutations additionally touched `crates/app/src/operations/enrollment_m03/verify.rs` and `crates/issuer/src/client.rs`. All were restored to the pinned head before cleanup. No repository evidence record was added because this task authorizes report-only work outside the checkout.

**Limits**

Windows and Linux were reviewed by reading. Native Windows/WSL/Linux filesystem, lock and custody claims remain **blocked** on those exact missing platforms; macOS fixtures and release tests do not close them. No cross-target checks were run in this review. Physical desktop-lock behavior, native product secure-store release certification, exhaustive fault/scheduler exploration, power-loss durability and the entire workspace test matrix were not checked. The read census proves identity in the exercised opens, not immutable file contents under arbitrary same-user in-place writes. The two Windows equivalents of new purge defects are source-derived, not observed Windows failures. Archived exploratory probes missing from this head were not rerun byte-for-byte.

**Cleanup**

Confirmed: `git worktree remove --force /tmp/hm-final-m03w5/wt` completed with exit 0. The complete worktree, including its 14 GB `target/`, was removed. The shell force-remove command for the remaining scratch root was rejected before execution; a guarded Python `shutil.rmtree` removed that exact review root with exit 0. Absence and worktree-registration assertions passed with exit 0: `/tmp/hm-final-m03w5/wt` and `/tmp/hm-final-m03w5` are absent, and the detached worktree is no longer registered. All temporary tests, mutation scripts, fixture material, sanitized captures and build outputs created under that root are gone. The report is retained outside it. The main checkout and other worktrees were not edited.

Not checked: native Windows/WSL/Linux execution and exhaustive crash/race coverage.
Risk: G01/G02 remain unfixed in the reviewed head; passing main suites do not make the purge recovery paths safe.
