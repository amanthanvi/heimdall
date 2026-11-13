# Heimdall M03 wave 5, rounds 3–6 — independent re-check

**Verdict: fix first.** The original consent, terminal, inventory and rendering scenarios now pass. W5-S01 is not closed on every path: the fence ends before deletion, and an allowed step-result request can start certificate issuance while it is held. Recovery finalization, event-payload validation and retirement after a new-item restore also have gaps.

Reviewed `baf2c88fb2033e668fbf2d8ae9611a60a5c076a6..7259203f79489cccf99b2fb7b0673523ce5a2c96`. All builds and tests used a detached worktree at the latter commit and its ordinary `target/`. Native host verified: Darwin arm64, Rust/Cargo 1.99.1, OpenSSH 10.5p1. Source paths below are repository-relative. `<repo>` denotes the original clone; `<scratch>` denotes `/tmp/hm-recheck-m03w5`.

I inspected the specification and changed code before reading ADR-0008 §§17.27–17.30 and the round notes. The notes are implementation claims, not validation evidence. This is an independent re-check performed without further delegation. No implementation fix, commit, push, main-checkout edit or other-worktree edit was made.

## 1. Original findings and original scenarios

“Verified” below is bounded to the exercised macOS fixtures and inspected shared code. It does not close native Windows/Linux claims.

| Original id | Result and evidence |
|---|---|
| W5-R01 | **verified** for the original scenario. `Txn::outstanding_obligations` includes non-final foreign removals (`crates/store/src/ext_m03.rs:855`), and bundle export reads them in the same transaction (`crates/app/src/operations/issuer_m03.rs:634`). The real inventory/guard and CLI tests for an abandoned foreign system-form removal pass. Removing foreign inventory enumeration makes the guard regression fail, exit 101. |
| W5-R02 | **verified** for the original scenario. The same inventory includes `late_write.is_some()` regardless of final state; `Inventory::read` consumes that inventory (`crates/heimdall/src/uninstall_cmd.rs:232`). Both future and passed not-after values without a subsequent absence observation are protected. The unit and CLI withdrawn-residual regressions pass; reverting the residual predicate fails, exit 101. C03 concerns a later removal/recovery route. |
| W5-R03 | **verified**. `crates/heimdall/src/issuer_cmd/session.rs:421` rejects noninteractive invocations before connecting/attending/opening the store. The redirected-stdin test retains a controlling terminal and covers the ceremony entries. Reverting to the old stdin bypass fails it, exit 101. |
| W5-R04 | **verified**. The CLI supplies the 120 s bound (`crates/heimdall/src/prompt.rs:17`; `crates/heimdall/src/issuer_cmd/session.rs:428`), and the actual terminal reader uses a bounded channel wait (`crates/issuer/src/ceremony.rs:282`). Short-bound registration and written-acknowledgement tests pass. An additional real production-bound registration test passed after about 121 s, CLI exit 3, no backup/item/registration. Extending the reader to an effectively unbounded wait fails the regression, exit 101. |
| W5-R05 | **verified**. Issuer registration carries the runtime lock text (`crates/heimdall/src/issuer_cmd/session.rs:254`); enrollment and generic decision completion fetch it and refuse approval if unavailable (`crates/heimdall/src/setup_cmd.rs:299`; `crates/heimdall/src/cli.rs:1795`). Native tests pass for continue and revoke-on-lock with saved limits on both issuer/enrollment surfaces. Reverting the issuer disclosure context fails, exit 101. |
| W5-R06 | **verified**. `crates/heimdall/src/output.rs:671` accepts the actual `items` wrapper and the compatibility spelling. The real-shape known/unknown-policy regression passes; reverting the wrapper support fails, exit 101. |
| W5-S01 | **blocked by C01 and C02**. The original two-CLI race at the purge confirmation now passes: it refuses with exit 4 and preserves the state/remote marker. The dispatcher request table, admission draining, connection-drop release and unresolved-step refusal also pass. These do not protect the complete deletion interval or all issuance routes; see the counterexamples below. |
| W5-S02 | **verified**. JSON mode includes the complete consent preview in the prompt (`crates/heimdall/src/enroll_cmd.rs:410`). Recorded disclosure prose also reaches setup/generic decisions (`crates/heimdall/src/setup_cmd.rs:306`; `crates/heimdall/src/cli.rs:1810`). Native JSON enrollment, removal, generic approval and uninstall preview regressions pass. Removing both enrollment-preview and recorded-prose wiring fails the JSON regression, exit 101. |
| W5-S03 | **verified**, the same conditional-lock repair as R05. Required text is checked before approval; the generic sentence is no longer accepted as the once-only disclosure. |
| W5-S04 | **verified**, the same timeout repair as R04, including the additional real 120 s test. |
| W5-S05 | **verified** on Unix. Cancellation/EOF remain distinct from an ordinary wrong answer (`crates/issuer/src/ceremony.rs:837`), and `show_passphrase` clears and exits on an error (`crates/issuer/src/ceremony.rs:1002`). Native Ctrl-C and EOF tests pass. Reverting cancellation to an ordinary false answer fails the retry regression, exit 101. Windows processed-input Ctrl-C behavior remains blocked on a native Windows interactive harness. |
| W5-S06 | **verified** for the original control-bearing filename scenario. Every CLI ceremony text write uses `SanitizedTerminal` (`crates/heimdall/src/issuer_cmd/session.rs:85`); only the ceremony's own clearing is passed through. The real-PTY path-control regression passes and fails when that sanitizer is bypassed, exit 101. |

### Fence time windows, alternate routes and connection loss

- **Observed:** acquisition waits for dispatcher admissions already past their check; the original confirmation race, broad request classification and unresolved remote-step tests pass. An outstanding/uncertain step prevents a purge at revalidation (`crates/heimdall/src/uninstall_cmd.rs:1488`). An allowed pre-fence result can still record the remote truth.
- **Observed:** dropping the holder connection releases its fence in the real endpoint test; another connection cannot release it. The corresponding dispatcher scope drop is `crates/runtime/src/dispatch.rs:251`. This confirms EOF/drop handling, not a separate SIGKILL campaign.
- **Observed:** a non-holder `StepResult` passed through the real dispatcher and signed two new verification certificates while the fence remained held (C02).
- **Observed:** direct application admission and verification reservation bypass the held fence. **Inferred production route:** a supervisor pass already past its one initial check can continue through the application without the dispatcher (`crates/app/src/operations/enrollment_m03/passes.rs:182`).
- **Inferred additional interval:** the grant reservation's `fence_check` precedes its asynchronous store write (`crates/app/src/operations.rs:11634`); it does not hold the admission guard across that write. A fence acquisition can overtake an unfenced ensure/background reservation already past that check. This interval was inspected, not separately scheduled in a probe.
- **Observed scheduled helper interleaving / inferred full CLI race:** after shutdown releases the runtime fence/instance lock, a replacement lock holder can write between the final read and `purge_state`; the purge still deletes the database (C01). The stop result is also absent from the deletion condition. A failed shutdown or dropped stop connection therefore does not itself prevent purge. A crashing uninstall before deletion stops its own further work; a crashing runtime or lost connection is not a durable fence for the surviving CLI.

## 2. Rounds 4–6 changes

**State machine.** The pure `withdrawn → removing` edge is restricted to an own account-form record carrying a residual (`crates/domain/src/enrollment.rs:1033`). Admission/decision prechecks require that residual and an attended session. The store cross-checks its presence, records the withdrawal/abandonment origin and retains it through held removal states (`crates/store/src/ext_m03.rs:956`). The normal removal path uses destination time strictly after not-after, a readable registry and no lock of the uncertain writer/unreadable lock before clearing the residual (`crates/app/src/operations/enrollment_m03/verify.rs:646`). Before/after, line-present, no-residual refusal and held-origin/index regressions pass. C03 identifies the manual-recovery path that skips this finalization.

**Issuing set.** Normal confirmed removal computes the “other verified or reverifying enrollment under this CA” condition and updates the set inside the same store transaction (`crates/app/src/operations/enrollment_m03/steps.rs:1702`). Thus an E5/remove commit ordering sees either the other trust or a later E5 adding it back. Existing real-issuance/login tests for abandoned and withdrawn old records, plus last-enrollment removal, pass. An added controlled interleaving put the newer record into `reverifying` while the old record's real removal committed; the CA stayed and the newer state was preserved, exit 0. This was a controlled state interleaving, not a stress/soak concurrency run. The recovered-last-removal counterexample in C03 fails.

**macOS keychain.** The new-item restore does not delete the old denied item. Free generation selection is attributes-only; the native add rejects a duplicate rather than overwriting. Exact recorded-locator reads are used by the child. Both `put` and `put_new_item` call the same native add helper, whose captured trusted-application requirement is checked against running code before writing (`crates/issuer/src/sys.rs:138`; `crates/issuer/src/store/macos.rs:402`). Native A/B-copy restore, read-denial, replaced-executable and exact-retirement tests pass. Reverting the identity guard and new-item restore independently fails their regressions. No wrong-item deletion or false confirmation of the old item's deletion was observed. The extended restore-then-retire test exposes C05: correct current-item deletion followed by incorrect completion/error reporting. The guard protects a changed code identity; an update retaining a valid designated requirement is intentionally allowed.

**Store payloads.** The two implemented checks work and their regressions detect their removal. The additional hold-carrying events required by ADR-0008 §17.30 item 8 remain unchecked; C04 reproduces all three mismatches.

**Local queries.** The constant is 10 s for all its callers, including SSH version/known-host queries and Git observation/writes (`crates/localenv/src/local_query.rs:35`). This intentionally increases the worst-case wait of each hung local query, and multiple queries can add up. The diff also adds timed-out-query names to `unreadable` and injectable observation diagnostics/bounds; it changes more than the numeric constant. Incomplete observations still fail closed and change the plan digest. The slow-Git regression passes at 10 s and fails when the default is reverted to 2 s, exit 101. Process containment, null stdin, environment selection and output bounds were preserved by inspection. No additional query correctness defect was established.

## New findings

### W5-C01 — high — The uninstall fence does not cover deletion

**Location:** `crates/heimdall/src/uninstall_cmd.rs:1394`, `:1402`, `:1409`, `:1636`, `:1668`; instance lock: `crates/runtime/src/instance.rs:34`.

**Failure scenario:** Uninstall stops the runtime and drops the connection that owns the fence, then performs an unlocked inventory read followed by database unlinking. A replacement runtime can obtain `service.lock` and admit work after that read. The old uninstall deletes the new records. Also, `stop_runtime` can return false on a failed/dropped shutdown request, but `stopped` is only reported; it is not required by the purge condition. That permits the same read/delete race against a runtime that never stopped.

**Probe and evidence:** `uninstall_cmd::tests::recheck_purge_must_exclude_writer_after_final_read`, **exit 101**. In a fresh disposable database it ran the real final inventory comparison, acquired the real replacement `InstanceLock`, inserted a foreign-removal obligation through a fresh `Store`, verified that obligation existed, then called the real `purge_state`. The database was deleted while the replacement lock was held. This is an explicitly scheduled production-helper interleaving, not a claim that two complete CLI processes naturally hit this instruction window. The missing exclusion and deletion are observed; full restarted-runtime data loss is inferred from the reachable sequence.

**Suggested fix:** Refuse purge unless shutdown was confirmed. Acquire and retain exclusion respected by runtime startup/writers before the final inventory/bundle read and hold it through deletion; if a replacement runtime wins that exclusion, refuse. Revalidation alone must not open another read/delete interval. Cover failed shutdown, connection loss and replacement startup in the regression.

### W5-C02 — medium — An allowed step result starts new verification issuance under the fence

**Location:** `crates/runtime/src/dispatch.rs:193`; `crates/app/src/operations/enrollment_m03/steps.rs:1025`; `crates/app/src/operations/verification_m03.rs:231`.

**Failure scenario:** An append was dispatched before the fence. Another connection reports its successful result while the fence is held. Reporting the result is intentionally allowed, but `enroll_step_result` then starts initial verification. `reserve_verification` has no fence check/admission guard, so it reserves and signs fresh certificates and contacts the verifier. This exceeds the allowed recording of the pre-fence remote truth.

**Probe and evidence:** `recheck_allowed_step_result_does_not_start_new_issuance_under_fence`, **exit 101**. The disposable loopback fixture ran the append, acquired the fence, then delivered `StepResult` through a non-holder `OperationsDispatcher`. Reply: `OK`; the fixture issuer signed **2** verification certificates, versus **0** before the request. This exercises the actual dispatcher and application follow-through; the issuer is the fixture TestCA-backed implementation. Separate probes also observed a successful direct verification reservation (`Ok(Ok(reserved))`) and direct enrollment admission (`APPROVAL_REQUIRED`) while held, each **exit 101** against the expected refusal.

**Suggested fix:** Record the result durably but defer verification/effectful follow-through until admission reopens. Fence both reservation tables at a shared application boundary, serialized with acquisition, and make supervisor work use it too. Preserve acceptance of the pre-fence result; do not discard it merely because verification must wait.

### W5-C03 — medium — Manual-recovery removal skips residual and issuing-set finalization

**Location:** `crates/app/src/operations/enrollment_m03/steps.rs:2030`, especially `:2064`; compare normal finalization at `:1685` and `:1702`.

**Failure scenario:** A removal takes effect but its result is lost. Three unproven fences leave it held with `lock_holder_unresolved`. After checking the owned fixture holder and removing its lock, the owner reconciles with `--after-manual-recovery`. A clean, post-not-after inspection shows absence and moves the record to `removed`, but this branch settles directly instead of applying the normal removal finalization. It retains an eligible withdrawn/abandoned late-write residual; for a last enrollment it also retains the CA in the pair's issuing set.

**Probe and evidence:** `recheck_manual_recovered_withdrawn_removal_clears_residual` and `recheck_manual_recovered_last_removal_drops_issuing_ca`, each failed within the combined **exit 101** run. Each ran a real disposable remote remove, reported a lost result, drove three unproven fences, removed only its test-owned lock/holder, and ran the real manual-recovery inspect. Both reached `removed`, with zero remote marker lines. One retained its past-not-after residual; the other retained its last issuing CA.

**Impact:** False outstanding obligations continue blocking cleanup, and the issuing-set report remains stale. The independent verified-enrollment selection still checks issuance eligibility; no unauthorized grant certificate was established by this probe.

**Suggested fix:** Share the post-removal cleanup with manual-recovery absence, while retaining its required manual-recovery transition/receipt. Apply D5 §6.7's observed-absence condition and the same atomic other-trust rule to every route reaching confirmed removal.

### W5-C04 — medium — The final ruled hold-payload checks are missing

**Location:** `crates/store/src/ext_m03.rs:322`; domain consumers `crates/domain/src/enrollment.rs:905`, `:914`, `:926`. Requirement: ADR-0008 §17.30 item 8.

**Failure scenario:** A held record stores `RegistryChanged`, but a caller supplies `TargetChangeApproved { hold: HostKeyChanged }` or a manual-recovery event claiming `LockHolderUnresolved`. The domain uses the supplied payload and the store's wildcard accepts it. The stored hold was not the one required for those exits.

**Probe and evidence:** `recheck_payloads_must_match_stored_hold`, **exit 101**. Separate fresh transactions observed all three mismatches commit: target change → `reverifying`; manual-recovery line present/Append → `applied_unverified`; manual-recovery line absent/Append → `withdrawn`. The two earlier payload checks' own permanent regression still passes. This is a store-boundary/defence-in-depth gap; current application callers derive these facts correctly, and no untrusted IPC route to forge the event directly was established.

**Suggested fix:** Extend `payload_agrees` to the other hold-carrying events and validate every restated stored fact, including recovery purpose where represented by persisted state/journal. Refuse mismatches before any record/event write; add byte-identical-before/after regressions for each.

### W5-C05 — medium — Retirement after new-item restore reports no effect after deleting the current key item

**Location:** `crates/heimdall/src/issuer_cmd.rs:579`; compare the denied-displaced-item helper at `:218` and runtime confirmation at `crates/app/src/operations/issuer_m03.rs:960`.

**Failure scenario:** Copy A creates a CA item; copy B loses access, restores to generation `#r1`, and records the new locator. B later retires the CA. `finish_retirement` deletes and confirms the current item, moving the CA to `retired`. It then applies `delete_exact` to the denied old displaced item. That read refuses, and the CLI returns exit 4 / `issuer_store_access_denied` / effect `none`, with advice to restore. The CA is already retired and its current item is already gone. Retrying continues encountering the denied old item.

**Probe and evidence:** Extended native product-file test `issuer::recheck_retire_after_new_item_restore_deletes_only_current_generation`, **exit 101**, reproduced three times (initial, diagnostic and explicit poststate runs). The final run first verified the CA was `retired`, the new generation was absent, and the old item remained; it then failed because the CLI returned 4 rather than successful retirement. The diagnostic run observed the JSON error's `effect_status: none`. No old-item deletion or old-item deletion confirmation occurred.

**Suggested fix:** Distinguish current and displaced work. Use the existing denied-displaced-item handling for the old item, retain its manual Keychain Access instruction/orphan listing, and report the completed current-item retirement accurately. If a later cleanup error must be returned, it must preserve/report the committed effects rather than claim none or advise an invalid restore.

## 3. Regression sensitivity and test quality

Seventeen isolated semantic reversions were made only in the disposable worktree, one at a time, with restoration in `finally`. **All seventeen failed a runtime test assertion with exit 101; none failed compilation and none matched zero tests.** These cover every original finding group and the principal new round-4–6 groups. The JSON mutation removed both newly redundant consent routes; leaving either full disclosure route intact would not recreate the original omission.

| Finding group | Semantic reversion in the disposable copy | Exit |
|---|---|---:|
| R01 | Omit foreign-removal inventory | 101 |
| R02 | Omit final records carrying late-write residuals | 101 |
| S01 | Bypass dispatcher fencing | 101 |
| R03 | Restore the non-TTY stdin bypass | 101 |
| R04/S04 | Extend the bounded reader to a 3600 s wait | 101 |
| S05 | Treat cancellation/EOF as a wrong answer | 101 |
| R05/S03 | Render issuer disclosures without runtime lock context | 101 |
| S02 | Remove JSON preview and recorded disclosure prose | 101 |
| S06 | Bypass the ceremony text sanitizer | 101 |
| R06 | Read only the synthetic/older destination wrapper | 101 |
| Executable identity | Omit the running-code requirement check | 101 |
| Access-denial restore | Refuse instead of creating/adopting a new item | 101 |
| Residual safety | Clear after a confirmed removal without the not-after condition | 101 |
| Issuing set | Always remove the CA, despite another trusted enrollment | 101 |
| Store payloads | Bypass the two implemented payload checks | 101 |
| Held origin | Omit recording the withdrawal/abandonment removal origin | 101 |
| Local-query bound | Restore the 2 s default | 101 |

The mutation commands/results are listed below. After all probes were removed, `git diff --exit-code` and clean status confirmed exact source restoration. The 169 CLI unit, 62 CLI, 8 ceremony, 33 store integration and 3 issuing-set tests passed again.

No weakened assertion or newly discarded test error was found in the exercised regressions. The ignored entries are named child-mode launchers, explicitly invoked by their parent tests. Unix/PTY and macOS keychain gating matches the fixture requirements; it is not evidence for native Windows. Late terminal writes after a timeout deliberately discard an I/O result because no reader may remain, while the tests separately assert no subsequent store/approval action. Permanent coverage is incomplete for C01–C05; passing original regressions does not close those paths.

## 4. Release/test isolation

`cargo build --release -p heimdall --locked` passed. `bash tools/validation/release-gate.sh` passed **26 probes**: 25 dynamic hook/selector invocations all exited **2** with the expected refusal before writing their fresh scratch home, plus the static localenv-hook reference check. The product-file selector was probed through service run, issuer status and issuer init. The release issuer library's formerly broken test now compiles and passes (21 tests); the three release deletion-gate integration tests pass, including refusal before test-store I/O.

**No test-only path reachable through the release executable was found.** The localenv injected-bound/callback APIs are still compiled library APIs; production configuration keeps them unset and no CLI/environment route sets them. The added gate for those APIs is a static reference check, not proof about arbitrary downstream library callers. No alternate allocator/linker/symbol-injection campaign was run.

## Commands and real exit codes

All Cargo commands below ran in the detached worktree. `run.py` captured/sanitized output and recorded the actual subprocess status; 101 denotes a failed Cargo test assertion, not the product CLI's exit. Source/specification navigation used `git diff/log`, `rg`, `sed`, `nl`, `cat` and small Python inspections. Navigation included no-match searches (1) and nonexistent exploratory paths (1/2); these were not validation passes. Versions and all material validation/probe commands are recorded here.

| Command | Exit | Observed result |
|---|---:|---|
| `git -C <repo> worktree add --detach <scratch>/wt 7259203f` | 0 | Exact detached review head created. |
| `cargo test -p heimdall --test e2e_cli_m03 --test e2e_enroll_m03 --test e2e_issuer_ceremony --locked` | 0 | 62 CLI + 81 enrollment + 8 ceremony passed; 5 child launchers ignored. |
| `cargo test -p heimdall-store -p heimdall-runtime -p heimdall-app -p heimdall-issuer --lib --locked` | 0 | 64 app + 22 issuer + 61 runtime + 21 store passed. |
| `cargo test -p heimdall-testkit --test integration_store_m03 --locked` | 0 | 33 passed. |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | Workspace/all-targets checks passed on unmodified head. |
| `cargo test -p heimdall --bin heimdall --locked` | 0 | 169 passed. |
| `cargo test -p heimdall-localenv --test integration_projection_git git_preview_digest_is_stable_under_a_slow_git --locked -- --exact` | 0 | 1 slow-Git regression passed. |
| `cargo build --release -p heimdall --locked` | 0 | Release executable built. |
| `bash tools/validation/release-gate.sh` | 0 | 26 probes passed; 25 dynamic child exits were 2. |
| `cargo test --release -p heimdall-issuer --lib --test integration_issuer_release_gate --locked` | 0 | 21 release library + 3 release deletion-gate tests passed. |
| `cargo test -p heimdall-testkit --test integration_store_m03 recheck_payloads_must_match_stored_hold --locked -- --exact` | 101 | Initial target-change mismatch accepted; assertion failed. |
| `cargo test -p heimdall --test e2e_enroll_m03 recheck_verification_reservation_refused_under_uninstall_fence --locked -- --exact` | 101 | Verification reservation succeeded under fence; assertion failed. |
| `cargo test -p heimdall --test e2e_enroll_m03 recheck_ --locked` | 101 | 4 intended counterexample assertions failed (reservation, admission, two recoveries). |
| `cargo test -p heimdall --bin heimdall uninstall_cmd::tests::recheck_purge_must_exclude_writer_after_final_read --locked -- --exact` | 101 | Scheduled writer after final read lost its disposable database. |
| `cargo test -p heimdall-testkit --test integration_store_m03 recheck_payloads_must_match_stored_hold --locked -- --exact` | 101 | All three mismatched hold events committed; assertion failed. |
| `cargo test -p heimdall --bin heimdall uninstall_cmd::tests::uninstall_purge_refuses_abandoned_foreign_system_form_removal --locked -- --exact` | 101 | Reverted fix: intended regression assertion failed; source restored. |
| `cargo test -p heimdall --bin heimdall uninstall_cmd::tests::uninstall_purge_refuses_withdrawn_late_write --locked -- --exact` | 101 | Reverted fix: intended regression assertion failed; source restored. |
| `cargo test -p heimdall-runtime --lib dispatch::tests::uninstall_fence_refuses_remote_and_ca_work_from_other_connections --locked -- --exact` | 101 | Reverted fix: intended regression assertion failed; source restored. |
| `cargo test -p heimdall --test e2e_cli_m03 issuer::issuer_ceremonies_refuse_redirected_stdin_with_a_terminal_attached --locked -- --exact` | 101 | Reverted fix: intended regression assertion failed; source restored. |
| `cargo test -p heimdall --test e2e_issuer_ceremony ceremony_registration_prompt_times_out_and_sends_nothing --locked -- --exact` | 101 | Reverted fix: intended regression assertion failed; source restored. |
| `cargo test -p heimdall-issuer --lib ceremony::tests::written_retries_only_a_wrong_answer --locked -- --exact` | 101 | Reverted fix: intended regression assertion failed; source restored. |
| `cargo test -p heimdall --test e2e_cli_m03 issuer::issuer_init_shows_the_continuing_lock_text_with_saved_limits --locked -- --exact` | 101 | Reverted fix: intended regression assertion failed; source restored. |
| `cargo test -p heimdall --test e2e_cli_m03 enroll::json_enroll_on_a_terminal_shows_disclosure_prose_before_the_prompt --locked -- --exact` | 101 | Reverted fix: intended regression assertion failed; source restored. |
| `cargo test -p heimdall --test e2e_cli_m03 issuer::issuer_init_backup_path_controls_never_reach_the_terminal --locked -- --exact` | 101 | Reverted fix: intended regression assertion failed; source restored. |
| `cargo test -p heimdall --bin heimdall output::tests::destination_list_renders_the_runtimes_items_shape --locked -- --exact` | 101 | Reverted fix: intended regression assertion failed; source restored. |
| `cargo test -p heimdall --test e2e_cli_m03 issuer::issuer_init_refuses_when_its_executable_is_replaced_mid_ceremony --locked -- --exact` | 101 | Reverted fix: intended regression assertion failed; source restored. |
| `cargo test -p heimdall --test e2e_cli_m03 issuer::recheck_real_120_second_registration_timeout --locked -- --exact` | 0 | Actual 120 s registration prompt refused with CLI exit 3; no backup/item. |
| `cargo test -p heimdall --test e2e_cli_m03 issuer::issuer_restore_after_access_denial_writes_a_new_item_and_lists_the_orphan --locked -- --exact` | 101 | Reverted fix: intended regression assertion failed; source restored. |
| `cargo test -p heimdall --test e2e_enroll_m03 abandoned_with_late_write_removed_before_not_after_keeps_residual --locked -- --exact` | 101 | Reverted fix: intended regression assertion failed; source restored. |
| `cargo test -p heimdall --test e2e_enroll_m03 removing_withdrawn_residual_keeps_ca_while_a_newer_verified_one_trusts_it --locked -- --exact` | 101 | Reverted fix: intended regression assertion failed; source restored. |
| `cargo test -p heimdall-testkit --test integration_store_m03 transition_refuses_event_payload_that_differs_from_the_stored_record --locked -- --exact` | 101 | Reverted fix: intended regression assertion failed; source restored. |
| `cargo test -p heimdall-testkit --test integration_store_m03 held_removal_with_origin_stays_outside_the_pair_ca_uniqueness_index --locked -- --exact` | 101 | Reverted fix: intended regression assertion failed; source restored. |
| `cargo test -p heimdall-localenv --test integration_projection_git git_preview_digest_is_stable_under_a_slow_git --locked -- --exact` | 101 | Reverted fix: intended regression assertion failed; source restored. |
| `cargo test -p heimdall --test e2e_enroll_m03 recheck_allowed_step_result_does_not_start_new_issuance_under_fence --locked -- --exact` | 101 | Allowed dispatcher StepResult signed 2 certificates under fence. |
| `cargo test -p heimdall --test e2e_enroll_m03 recheck_removal_keeps_ca_during_other_reverification --locked -- --exact` | 0 | Controlled reverifying/removal interleaving passed. |
| `cargo test -p heimdall --test e2e_cli_m03 issuer::recheck_retire_after_new_item_restore_deletes_only_current_generation --locked -- --exact` | 101 | Initial extended native retirement probe: CLI exit 4. |
| `cargo test -p heimdall --test e2e_cli_m03 issuer::recheck_retire_after_new_item_restore_deletes_only_current_generation --locked -- --exact` | 101 | Same probe; observed access-denied JSON with effect none. |
| `cargo test -p heimdall --test e2e_cli_m03 issuer::recheck_retire_after_new_item_restore_deletes_only_current_generation --locked -- --exact` | 101 | Verified retired CA/current item gone/old item preserved before failed CLI-success assertion. |
| `git diff --exit-code && git status --porcelain && git rev-parse HEAD` | 0 | Exact head and clean diff/status verified after removing probes. |
| `cargo test -p heimdall-testkit --test integration_store_m03 --locked` | 0 | 33 store integration tests passed again. |
| `cargo test -p heimdall --test e2e_enroll_m03 removing_ --locked` | 0 | 3 issuing-set regressions passed again. |
| `cargo test -p heimdall --bin heimdall --test e2e_cli_m03 --test e2e_issuer_ceremony --locked` | 0 | 169 unit + 62 CLI + 8 ceremony passed again. |
| `du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist` | 1 | No matching prototype build-output directories; du reported missing patterns. |
| `du -sh target` | 0 | 11 GiB target before cleanup; all removed with worktree. |
| `rustc --version && cargo --version && ssh -V && uname -sm` | 0 | Rust/Cargo 1.99.1, OpenSSH 10.5p1, Darwin arm64. |
| `git diff --exit-code && git status --porcelain` | 0 | Clean disposable source after final validation. |

Additional inspection confirmed zero running executables under the review worktree prefix and zero runtime `.keychain`/`.keychain-db` files in the scratch tree before removal. Prototype outputs were absent; the 11 GiB build output belonged entirely to this worktree.

## Limits and changed files

- **blocked: native Windows, WSL and Linux hosts/harnesses unavailable in this review.** Those implementations were reviewed by reading. No emulation/cross-build is credited as native lock, secure-store or console proof.
- No full workspace test run, physical desktop-lock test, power-loss test, fuzzing campaign or every-signal crash matrix was performed. Clippy covered all workspace targets; selected native suites supplied behavioral evidence.
- The new deletion-window probe schedules actual inventory/store/lock/purge helpers. A naturally timed full CLI restart race and the failed-shutdown race are source-derived implications, explicitly not claimed as observed two-process outcomes.
- The new issuance/recovery probes use the existing disposable loopback/TestCA fixture and actual application/dispatcher code. They do not claim production keychain-backed issuer execution; the separate issuer CLI/keychain tests exercise the native product store in an isolated file keychain.
- Tests used generated fixture keys, scratch homes/stores, fixture agents and loopback sshd only. No owner's SSH configuration/key/agent, login keychain, password manager or real server was a test target. Test-owned children were managed by exact handles; no blanket process stopping occurred. No canary occurrence was observed in the emitted validation summaries/product scans.
- **Persistent changed file:** the requested external report only. Temporary probes touched `crates/heimdall/src/uninstall_cmd.rs`, `tests/e2e/cli_m03/issuer.rs`, `tests/e2e/enroll_m03.rs` and `tests/integration/store_m03.rs` in the disposable worktree. Temporary mutation edits affected the production files named in the commands/results and were restored individually. All temporary source, scripts, captures and fixtures are removed by cleanup. No repository evidence record was written because this was report-only work outside the main checkout.

## Cleanup confirmation

**Confirmed, exit 0:** `git -C <repo> worktree remove --force /tmp/hm-recheck-m03w5/wt` removed the detached worktree and its complete 11 GiB `target/`. Exact-path Python removal of `/tmp/hm-recheck-m03w5` then completed, exit 0. Assertions confirmed the scratch root was absent, the worktree registration was gone, the original checkout was clean, and this report remained. No runtime keychain file remained under the scratch root before removal; the fixture teardown removed its disposable keychains. No pre-existing process was stopped.

| Cleanup command | Exit | Observed result |
|---|---:|---|
| `git -C <repo> worktree remove --force /tmp/hm-recheck-m03w5/wt` | 0 | Worktree and entire build output removed. |
| `python3` exact-path scratch removal, worktree-list/status and report assertions | 0 | Scratch absent; unregistered; main checkout clean; report retained. |


Not checked: native Windows/Linux/WSL, physical lock behavior and the full workspace test suite.
Risk: W5-S01 still permits work outside its intended fence, with a remaining deletion interval; C03–C05 also require fixes before merge.
